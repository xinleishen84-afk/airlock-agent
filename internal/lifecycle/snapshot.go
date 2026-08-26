package lifecycle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// 网关状态持久化。
//
// # 什么该持久化
//
// 重启后丢失会造成**真实损失**的状态：
//
//	预算已花费额度  —— 丢了就是钱。一个 $500/月 的 Tier1 预算，
//	                   实例重启后忘记已花 $480，会再花一个 $500
//	限流窗口用量    —— 丢了就是保护失效。滚动更新后每个新实例
//	                   都发放全新配额，Agent 的相关性突发会直接打满 GPU
//
// # 什么绝不能持久化
//
// **PII 脱敏映射**。SessionVault 里存的是「占位符 -> 真实姓名/手机/身份证」，
// 它一旦落盘或进 Redis，就等于把脱敏网关变成了 PII 数据库——
// 一次备份泄露、一次运维误查，防线全废。
//
// 该类型在 internal/pii 里已从类型层面禁止序列化（Purge 前无法导出），
// 这里再从数据模型上确认一次：Snapshot 结构体里没有任何字段能装下它。
// 会话中断的代价是「重启后同一会话的占位符编号重排」——
// 对模型只是换了个代号，远小于持久化 PII 的风险。
//
// # Agent 会话状态归谁
//
// Agent 的 scratchpad 与中间推理状态属于业务编排层（Java/Go），
// 不在网关。网关是无状态转发面，它持久化的只有自己拥有的计量数据。
// 把 Agent 状态塞进网关会让它变成有状态服务，横向扩容随即失效。

// SnapshotVersion 是快照格式版本。
// 格式不兼容时新版本应拒绝加载旧快照，而不是按字段缺失静默降级——
// 那会让预算被悄悄清零。
const SnapshotVersion = 1

// Snapshot 是可持久化的网关计量状态。
//
// 刻意只有计量数据。任何新增字段都要能回答：
// 它丢失会造成实际损失吗？它含有用户内容吗？
// 第一问答否就不该存，第二问答是就绝不能存。
type Snapshot struct {
	Version    int       `json:"version"`
	SavedAt    time.Time `json:"saved_at"`
	InstanceID string    `json:"instance_id"`

	// BudgetSpent 是各梯队已花费金额（美元），键为梯队编号
	BudgetSpent map[string]float64 `json:"budget_spent,omitempty"`

	// RateLimitUsed 是各限流主体在当前窗口内的已用 token 数
	RateLimitUsed map[string]int64 `json:"rate_limit_used,omitempty"`
}

// Age 返回快照距今时长。
func (s *Snapshot) Age() time.Duration { return time.Since(s.SavedAt) }

// Store 是状态存储抽象。
//
// 只定义接口、内置文件实现：Redis / etcd 客户端是重依赖，
// 网关是安全组件，不该为一个可选功能把依赖树撑大。
// 多副本部署需要外部存储时，实现本接口即可接入。
type Store interface {
	Save(*Snapshot) error
	Load() (*Snapshot, error)
	Name() string
}

// FileStore 把快照写到本地文件。
//
// 适用于单实例部署，或挂载了持久卷的场景。K8s 里若用 emptyDir，
// 快照会随 Pod 一起消失——那种部署需要换成外部 Store 实现。
type FileStore struct {
	path string
}

// NewFileStore 创建文件存储。
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

// Name 返回存储标识。
func (f *FileStore) Name() string { return "file:" + f.path }

// Save 原子写入快照。
//
// 先写临时文件再 rename：停机时进程随时可能被 SIGKILL，
// 直接覆写会留下一个半截文件，下次启动加载时预算数据就是错的。
func (f *FileStore) Save(s *Snapshot) error {
	if s == nil {
		return fmt.Errorf("快照为空")
	}
	s.Version = SnapshotVersion
	s.SavedAt = time.Now()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化快照失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return fmt.Errorf("创建快照目录失败: %w", err)
	}

	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("写入临时快照失败: %w", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("提交快照失败: %w", err)
	}
	return nil
}

// Load 读取快照。文件不存在时返回 (nil, nil)——首次启动是正常情况。
func (f *FileStore) Load() (*Snapshot, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取快照失败: %w", err)
	}

	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("解析快照失败: %w", err)
	}
	if s.Version != SnapshotVersion {
		// 版本不符时拒绝加载，而不是按字段缺失静默降级——
		// 那会让预算被悄悄清零，且没有任何迹象
		return nil, fmt.Errorf("快照版本 %d 与当前版本 %d 不符，拒绝加载",
			s.Version, SnapshotVersion)
	}
	return &s, nil
}

// NopStore 是不做任何持久化的实现，用于未配置存储的部署。
type NopStore struct{}

// Name 返回存储标识。
func (NopStore) Name() string { return "none" }

// Save 什么都不做。
func (NopStore) Save(*Snapshot) error { return nil }

// Load 返回空快照。
func (NopStore) Load() (*Snapshot, error) { return nil, nil }
