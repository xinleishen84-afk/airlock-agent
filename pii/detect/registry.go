package detect

import (
	"fmt"
	"sort"
	"sync"
)

// Registry manages the set of active recognizers, built-in and custom alike.
// 管理全部生效的识别器，内置与自定义一视同仁。
//
// # Why a registry rather than a hardcoded table
// # 为什么要注册中心而不是硬编码表
//
// Every deployment has entity types nobody upstream can anticipate: an internal
// employee-ID format, a contract number, a customer code. If the only way to add
// one is to patch this library's source, adopters end up maintaining a fork —
// and a forked security component stops receiving upstream fixes.
// 每个部署都有上游预料不到的实体类型：内部工号格式、合同编号、客户代码。
// 如果加一个识别器的唯一途径是改本库源码，采纳方最终会维护一个 fork——
// 而一个被 fork 的安全组件从此收不到上游修复。
//
// The registry lets a custom recognizer be registered from outside, on equal
// footing with the built-ins.
// 注册中心让自定义识别器从外部注册，与内置识别器地位相同。
type Registry struct {
	mu          sync.RWMutex
	recognizers map[string]Recognizer
}

// Recognizer detects one class of entity.
// 检测某一类实体。
//
// Deliberately narrower than Detector: a Detector may aggregate many
// recognizers, while a Recognizer handles exactly one entity type. Keeping them
// separate means a custom recognizer only implements what it actually needs.
// 刻意比 Detector 更窄：Detector 可以聚合多个识别器，
// 而 Recognizer 只负责一种实体类型。分开的好处是自定义识别器
// 只需实现它真正需要的东西。
type Recognizer interface {
	// Name returns a unique identifier, used for registration and audit.
	// 返回唯一标识，用于注册与审计。
	Name() string

	// EntityType returns the entity type this recognizer produces.
	// 返回本识别器产出的实体类型。
	EntityType() EntityType

	// Recognize finds entities in the text. Offsets must be byte offsets into
	// the input, and text[Start:End] must equal Value exactly.
	// 在文本中查找实体。偏移量必须是输入的字节偏移，
	// 且 text[Start:End] 必须精确等于 Value。
	Recognize(text string) ([]Entity, error)
}

// NewRegistry creates an empty registry.
// 创建空注册中心。
func NewRegistry() *Registry {
	return &Registry{recognizers: map[string]Recognizer{}}
}

// Register adds a recognizer. Registering a duplicate name is an error rather
// than a silent overwrite — a silently replaced recognizer means an entity type
// stops being detected, with no signal at all.
// 注册一个识别器。重名视为错误而非静默覆盖——
// 被静默替换的识别器意味着某类实体从此不再被检出，且毫无征兆。
func (r *Registry) Register(rec Recognizer) error {
	if rec == nil {
		return fmt.Errorf("识别器不能为 nil / recognizer must not be nil")
	}
	name := rec.Name()
	if name == "" {
		return fmt.Errorf("识别器必须有名字 / recognizer must have a name")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.recognizers[name]; dup {
		return fmt.Errorf("识别器 %q 已注册 / recognizer %q already registered", name, name)
	}
	r.recognizers[name] = rec
	return nil
}

// MustRegister is Register that panics on error, for package-level init.
// 是会 panic 的 Register，供包级初始化使用。
func (r *Registry) MustRegister(rec Recognizer) {
	if err := r.Register(rec); err != nil {
		panic(err)
	}
}

// Get returns a registered recognizer by name.
// 按名称取出已注册的识别器。
func (r *Registry) Get(name string) (Recognizer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.recognizers[name]
	return rec, ok
}

// Remove unregisters a recognizer by name.
// 按名注销一个识别器。
//
// Useful for turning off a built-in that misfires in a particular deployment:
// an internal-network gateway may not want IP addresses redacted at all.
// 用于关闭在特定部署下误报的内置识别器：
// 内网网关可能根本不需要脱敏 IP 地址。
func (r *Registry) Remove(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.recognizers[name]; !ok {
		return false
	}
	delete(r.recognizers, name)
	return true
}

// Names returns every registered name, sorted.
// 返回全部已注册的名字（已排序）。
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.recognizers))
	for name := range r.recognizers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// CoveredTypes returns the union of entity types the registry can detect.
// 返回注册中心能检出的实体类型并集。
func (r *Registry) CoveredTypes() []EntityType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[EntityType]bool{}
	var out []EntityType
	for _, rec := range r.recognizers {
		if t := rec.EntityType(); !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Name implements Detector.
// 实现 Detector 接口。
func (r *Registry) Name() string { return "registry" }

// Detect runs every registered recognizer and resolves overlaps.
// 运行全部已注册的识别器并消解重叠。
//
// A single recognizer's failure propagates: silently dropping its results would
// weaken protection with no signal, which is worse than failing the request.
// 单个识别器故障会上抛：静默丢弃它的结果会在无征兆的情况下削弱防护，
// 那比让请求失败更糟。
func (r *Registry) Detect(text string) ([]Entity, error) {
	r.mu.RLock()
	recs := make([]Recognizer, 0, len(r.recognizers))
	for _, rec := range r.recognizers {
		recs = append(recs, rec)
	}
	r.mu.RUnlock()

	var found []Entity
	for _, rec := range recs {
		got, err := rec.Recognize(text)
		if err != nil {
			return nil, fmt.Errorf("识别器 %s 执行失败 / recognizer %s failed: %w",
				rec.Name(), rec.Name(), err)
		}
		found = append(found, got...)
	}
	return ResolveOverlaps(found), nil
}

// AsDetector adapts a Recognizer to the Detector interface without resolving
// overlaps.
// 把 Recognizer 适配为 Detector，且不做重叠消解。
//
// # 为什么不用 Registry 包一层
// # Why not wrap it in a Registry
//
// Registry.Detect 内部会跑 ResolveOverlaps。对一个产出**候选**的识别器来说，
// 那是错的：姓氏识别器同时产出「尉迟恭」与「尉迟恭负」，而「长者优先」
// 会让多吞了一个动词的那个赢——等下游的证据链拿到结果，正确的那个已经没了。
//
// 实测：Core 二进制把「尉迟恭负责本次验收」脱敏成
// 「ANONYMIZED_NAME_1责本次验收」。而且这次消解发生在两个地方——
// Registry 里一次，CompositeDetector 里又一次；只堵住后者不够。
//
// Registry.Detect runs ResolveOverlaps internally, which is wrong for a
// recognizer that emits candidates: the surname recognizer produces both
// 尉迟恭 and 尉迟恭负, and length-first resolution lets the one that swallowed
// a verb win before the evidence chain ever sees the alternative. Measured, and
// it happens in two places — the Registry and the CompositeDetector — so
// blocking only the latter is not enough.
func AsDetector(r Recognizer) Detector {
	return recognizerDetector{inner: r}
}

// recognizerDetector wraps one Recognizer.
type recognizerDetector struct{ inner Recognizer }

// Name implements Detector.
func (d recognizerDetector) Name() string { return d.inner.Name() }

// CoveredTypes implements Detector.
func (d recognizerDetector) CoveredTypes() []EntityType {
	return []EntityType{d.inner.EntityType()}
}

// Detect implements Detector, returning every candidate unresolved.
// 实现 Detector，原样返回全部候选。
func (d recognizerDetector) Detect(text string) ([]Entity, error) {
	return d.inner.Recognize(text)
}
