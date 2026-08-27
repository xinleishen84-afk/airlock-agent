package sidecar

import (
	"sort"
	"sync"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// # The admin inspector
// # 管理面探查器
//
// An operations console needs to see what the gateway is actually enforcing:
// which packs loaded, which rules fire, where the audit trail goes. What it
// must never see is the material that makes any of it work.
// 运营控制台需要看到网关实际在执行什么：装了哪些包、哪些规则在命中、
// 审计轨迹去了哪。它绝不能看到的，是让这一切得以运作的那些材料。
//
// # The three things a snapshot must not contain
// # 快照绝不能包含的三样东西
//
//  1. Keys and salts. Obvious, and the one everybody remembers.
//     密钥与盐。显而易见，也是所有人都记得的那个。
//
//  2. Mapping records. The vault and the token store hold placeholder → real
//     value; an endpoint that returns them is a PII export with a dashboard in
//     front of it.
//     映射记录。保险库与令牌库持有「占位符 → 真实值」；
//     一个把它们返回出去的接口，就是一次带看板界面的 PII 导出。
//
//  3. Roster entries. This is the one that gets missed. The name roster is a
//     list of employee and customer names — it is not configuration that
//     happens to contain PII, it is PII, loaded as configuration. A snapshot
//     that echoes back "which names are we protecting" hands over the exact
//     list the gateway exists to protect.
//     名册条目。这是会被漏掉的那个。姓名名册就是一份员工与客户姓名清单——
//     它不是「碰巧含有 PII 的配置」，它就是 PII，只不过以配置的形式加载。
//     一份回显「我们在保护哪些姓名」的快照，
//     等于把网关存在的理由那份清单原样交了出去。
//
// So every count below is a count, and there is a test that walks this struct
// by reflection and refuses any new field that could carry a value.
// 因此下面每一个数字都只是数字，并且有一条用例用反射遍历这个结构体，
// 拒绝任何可能装下原值的新字段。

// Snapshot is a read-only view of what the gateway is enforcing.
// 是网关正在执行什么的只读视图。
type Snapshot struct {
	// SchemaVersion lets a console detect a shape change.
	SchemaVersion string `json:"schema_version"`

	// GeneratedAt is when the snapshot was taken.
	GeneratedAt time.Time `json:"generated_at"`

	// Uptime is how long this process has been serving.
	UptimeSeconds int64 `json:"uptime_seconds"`

	// Isolation describes the tenant model actually in effect.
	// 描述实际生效的租户模型。
	Isolation IsolationView `json:"isolation"`

	// Detection describes the recognizers in place.
	// 描述已装配的识别器。
	Detection DetectionView `json:"detection"`

	// Redaction describes the strategy matrix.
	// 描述脱敏策略矩阵。
	Redaction RedactionView `json:"redaction"`

	// Audit describes where the trail goes.
	// 描述审计轨迹去了哪。
	Audit AuditView `json:"audit"`

	// Runtime holds live counters.
	// 存放运行时计数。
	Runtime RuntimeView `json:"runtime"`
}

// IsolationView describes the tenant model.
// 描述租户模型。
type IsolationView struct {
	// Resolver is the resolver's own name, from a closed set of implementations
	// (for example "header:X-Tenant-Id"), not a tenant identifier.
	// 是解析器自身的名字，取自一组封闭的实现（例如 "header:X-Tenant-Id"），
	// 不是某个租户标识。
	Resolver string `json:"resolver"`

	// ActiveTenants counts tenants with live sessions.
	// 统计有活跃会话的租户数量。
	//
	// 只给数量，不给名单。租户名单本身就是客户名单——
	// 一份「我们服务了哪些公司」的清单，是这家公司不会想让人拉走的东西。
	// A count, not a list. The tenant list is a customer list, which is not
	// something the company wants exported.
	ActiveTenants int `json:"active_tenants"`
}

// DetectionView describes the detection layer.
// 描述检测层。
type DetectionView struct {
	// Jurisdictions are the configured country pack codes.
	// 是已配置的国家包代码。
	Jurisdictions []string `json:"jurisdictions"`

	// Recognizers counts recognizers by name.
	// 按名称列出识别器。
	Recognizers []RecognizerHealth `json:"recognizers"`

	// CoveredTypes are the entity types some recognizer covers.
	CoveredTypes []string `json:"covered_types"`

	// CoverageGaps are entity types nothing covers.
	//
	// 非空意味着这几类 PII 在完全裸奔。它必须出现在控制台第一屏，
	// 而不是埋在某个日志里。
	// A non-empty list means those types are fully exposed. It belongs on the
	// console's first screen, not buried in a log.
	CoverageGaps []string `json:"coverage_gaps,omitempty"`

	// RosterSizes reports how many entries each roster holds.
	// 报告每份名册有多少条目。
	//
	// 数量，不是条目。名册就是姓名清单——回显它等于导出 PII。
	// Counts, never entries: the roster is a list of names.
	RosterSizes map[string]int `json:"roster_sizes,omitempty"`
}

// RecognizerHealth is one recognizer's operational state.
// 是一条识别器的运行状态。
type RecognizerHealth struct {
	Name string `json:"name"`
	Type string `json:"entity_type"`

	// Source is "pack:CN" or "tenant:acme-corp".
	// 取值形如 "pack:CN" 或 "tenant:acme-corp"。
	Source string `json:"source"`

	// Hits is how many times it has matched since start.
	// 是启动以来的命中次数。
	Hits int64 `json:"hits"`

	// NeverFired marks a recognizer that has never matched.
	// 标记一条从未命中过的识别器。
	//
	// 对国家包里的规则，这常常只说明这个部署没有那类数据。
	// 对租户自定义规则，它更可能说明规则写错了——而写错的规则不报错，
	// 它只是安静地什么都不拦。这一列存在，就是为了让「安静」变得可见。
	// For a pack rule this often just means this deployment has no such data.
	// For a tenant rule it more likely means the rule is wrong — and a wrong
	// rule does not error, it quietly catches nothing. This column exists to
	// make that quiet visible.
	NeverFired bool `json:"never_fired"`
}

// RedactionView describes the strategy matrix.
// 描述脱敏策略矩阵。
type RedactionView struct {
	// Destinations lists the configured flows.
	Destinations []DestinationView `json:"destinations"`

	// TokenStore is the driver's kind, never its contents.
	// 是驱动的种类，绝不是它的内容。
	TokenStore string `json:"token_store"`

	// TokenCount is how many tokens are outstanding, when the driver can say.
	// 是当前在册的令牌数量（驱动能给出时）。
	//
	// 数量，不是令牌，更不是它们背后的值。
	// A count, not the tokens, and certainly not the values behind them.
	TokenCount int `json:"token_count,omitempty"`
}

// DestinationView is one flow's configuration.
// 是一条链路的配置。
type DestinationView struct {
	Name     string            `json:"name"`
	Restores bool              `json:"restores"`
	Default  string            `json:"default_strategy"`
	ByType   map[string]string `json:"by_type,omitempty"`
}

// AuditView describes the audit trail.
// 描述审计轨迹。
type AuditView struct {
	// Sink is where events go, by name.
	Sink string `json:"sink"`

	// Emitted, Dropped and Failed are delivery counters.
	//
	// Dropped 非零意味着轨迹上有洞。控制台必须看得见它——
	// 一个没人知道的问责缺口，比一个看得见的更糟。
	// A non-zero Dropped means the trail has holes, and the console must show
	// it: an accountability gap nobody knows about is worse than a visible one.
	Emitted int64 `json:"emitted"`
	Dropped int64 `json:"dropped"`
	Failed  int64 `json:"failed"`
}

// RuntimeView holds live counters.
// 存放运行时计数。
type RuntimeView struct {
	ActiveSessions int   `json:"active_sessions"`
	RedactCalls    int64 `json:"redact_calls"`
	RestoreCalls   int64 `json:"restore_calls"`
	BlockedCalls   int64 `json:"blocked_calls"`
}

// SnapshotSchema identifies the snapshot format.
// 标识快照格式。
const SnapshotSchema = "airlock.admin.v1"

// recognizerStats tracks per-recognizer hit counts.
// 跟踪每条识别器的命中数。
type recognizerStats struct {
	mu   sync.RWMutex
	hits map[string]int64
}

func newRecognizerStats() *recognizerStats {
	return &recognizerStats{hits: map[string]int64{}}
}

// record adds hits from one redaction pass.
// 累加一次脱敏的命中。
func (s *recognizerStats) record(entities []detect.Entity) {
	if len(entities) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entities {
		if e.Detector != "" {
			s.hits[e.Detector]++
		}
	}
}

// snapshot returns a copy of the counters.
// 返回计数的副本。
func (s *recognizerStats) snapshot() map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int64, len(s.hits))
	for k, v := range s.hits {
		out[k] = v
	}
	return out
}

// Inspect builds a snapshot of the running gateway.
// 构建正在运行的网关的快照。
func (s *Server) Inspect() Snapshot {
	snap := Snapshot{
		SchemaVersion: SnapshotSchema,
		GeneratedAt:   time.Now().UTC(),
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
		Isolation: IsolationView{
			Resolver:      s.opts.TenantResolver.Name(),
			ActiveTenants: s.vaults.ActiveTenants(),
		},
		Runtime: RuntimeView{
			ActiveSessions: s.vaults.ActiveSessions(),
			RedactCalls:    s.redactCalls.Load(),
			RestoreCalls:   s.restoreCalls.Load(),
			BlockedCalls:   s.blockedCalls.Load(),
		},
	}

	snap.Detection = s.detectionView()
	snap.Redaction = s.redactionView()
	snap.Audit = s.auditView()
	return snap
}

// detectionView describes the detection layer.
// 描述检测层。
func (s *Server) detectionView() DetectionView {
	view := DetectionView{Jurisdictions: s.opts.Jurisdictions}

	for _, t := range s.opts.Detector.CoveredTypes() {
		view.CoveredTypes = append(view.CoveredTypes, string(t))
	}
	sort.Strings(view.CoveredTypes)

	if comp, ok := s.opts.Detector.(detect.GapReporter); ok {
		for _, t := range comp.Missing() {
			view.CoverageGaps = append(view.CoverageGaps, string(t))
		}
	}
	if len(s.opts.RosterSizes) > 0 {
		view.RosterSizes = make(map[string]int, len(s.opts.RosterSizes))
		for k, v := range s.opts.RosterSizes {
			view.RosterSizes[k] = v
		}
	}

	hits := s.recognizers.snapshot()
	for _, r := range s.opts.RecognizerCatalog {
		h := hits[r.Name]
		view.Recognizers = append(view.Recognizers, RecognizerHealth{
			Name: r.Name, Type: r.Type, Source: r.Source,
			Hits: h, NeverFired: h == 0,
		})
	}
	sort.Slice(view.Recognizers, func(i, j int) bool {
		return view.Recognizers[i].Name < view.Recognizers[j].Name
	})
	return view
}

// redactionView describes the strategy matrix.
// 描述脱敏策略矩阵。
func (s *Server) redactionView() RedactionView {
	view := RedactionView{TokenStore: "none"}

	if s.opts.Matrix != nil {
		for _, name := range s.opts.Matrix.Destinations() {
			flow, err := s.opts.Matrix.Flow(anonymize.Destination(name))
			if err != nil {
				continue
			}
			d := DestinationView{
				Name: name, Restores: flow.Restores, Default: flow.Default.Name(),
			}
			if len(flow.ByType) > 0 {
				d.ByType = make(map[string]string, len(flow.ByType))
				for typ, strategy := range flow.ByType {
					d.ByType[string(typ)] = strategy.Name()
				}
			}
			view.Destinations = append(view.Destinations, d)
		}
	} else {
		view.Destinations = append(view.Destinations, DestinationView{
			Name: "default", Restores: true, Default: "mask",
		})
	}

	switch store := s.opts.TokenStore.(type) {
	case nil:
	case *anonymize.MemoryTokenStore:
		view.TokenStore = "memory"
		view.TokenCount = store.Size()
	default:
		// 具体驱动名不暴露内容，只说明用的是哪一类存储
		view.TokenStore = "external"
	}
	return view
}

// auditView describes the audit trail.
// 描述审计轨迹。
func (s *Server) auditView() AuditView {
	view := AuditView{Sink: "none"}
	if s.opts.Auditor != nil {
		view.Sink = s.opts.Auditor.SinkName()
	}
	view.Emitted = s.auditEmitted.Load()
	view.Dropped = s.auditDropped.Load()
	return view
}
