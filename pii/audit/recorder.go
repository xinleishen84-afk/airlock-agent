package audit

import (
	"context"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// Recorder assembles and emits audit events.
// 组装并发出审计事件。
//
// It exists so the call sites cannot build an event by hand. A hand-built event
// is one where somebody eventually passes the wrong string into the wrong
// field, and the field that receives it is shipped to the SIEM.
// 它的存在是为了让调用点无法手工拼装事件。
// 手工拼装的事件里，总会有人在某一天把错的字符串传进错的字段——
// 而接住它的那个字段是要发到 SIEM 去的。
type Recorder struct {
	sink Sink
	fp   *Fingerprinter

	// onError receives sink failures.
	// 接收 sink 故障。
	//
	// A failed audit emission must reach the operator: it means the trail has a
	// hole, and a hole nobody knows about is worse than one they can see. It
	// must not fail the request, though — the redaction already happened
	// correctly, and blocking a correctly-redacted request because the SIEM is
	// slow trades a real outage for a bookkeeping problem.
	// 审计发送失败必须让运维知道：它意味着轨迹上有个洞，
	// 而没人知道的洞比看得见的洞更糟。但它不能让请求失败——
	// 脱敏本身已经正确完成，因为 SIEM 慢就阻断一个已正确脱敏的请求，
	// 是拿一次真实的服务中断去换一个记账问题。
	onError func(error)
}

// NewRecorder builds a recorder.
// 构造记录器。
func NewRecorder(sink Sink, fp *Fingerprinter, onError func(error)) *Recorder {
	if sink == nil {
		sink = NopSink{}
	}
	if onError == nil {
		onError = func(error) {}
	}
	return &Recorder{sink: sink, fp: fp, onError: onError}
}

// SinkName reports where the trail goes, for the admin snapshot.
// 报告轨迹去了哪，供管理快照使用。
func (r *Recorder) SinkName() string { return r.sink.Name() }

// Close releases the sink.
// 释放 sink。
func (r *Recorder) Close() error { return r.sink.Close() }

// Redaction describes one outbound redaction, in counts only.
// 用纯计数描述一次出站脱敏。
type Redaction struct {
	Tenant      anonymize.Tenant
	Session     string
	Destination string
	Entities    []detect.Entity
	TypeCounts  map[string]int
	Strategies  map[string]int
	Duration    time.Duration
}

// EmitRedaction records an outbound redaction.
// 记录一次出站脱敏。
func (r *Recorder) EmitRedaction(ctx context.Context, in Redaction) {
	e := r.base(in.Tenant, in.Session, ActionRedact, OutcomeOK)
	e.Destination = in.Destination
	e.Entities = copyCounts(in.TypeCounts)
	e.Strategies = copyCounts(in.Strategies)
	e.Recognizers = countRecognizers(in.Entities)
	e.DurationMicros = in.Duration.Microseconds()
	r.emit(ctx, e)
}

// Restoration describes one inbound restoration.
// 描述一次入站复原。
type Restoration struct {
	Tenant   anonymize.Tenant
	Session  string
	Restored int
	Phantom  int
	Duration time.Duration
}

// EmitRestoration records an inbound restoration.
// 记录一次入站复原。
func (r *Recorder) EmitRestoration(ctx context.Context, in Restoration) {
	e := r.base(in.Tenant, in.Session, ActionRestore, OutcomeOK)
	e.Restored = in.Restored
	e.Phantom = in.Phantom
	e.DurationMicros = in.Duration.Microseconds()
	r.emit(ctx, e)
}

// EmitBlock records a fail-closed block.
// 记录一次 fail-closed 阻断。
//
// class is an enumerated reason. The caller keeps the underlying error for its
// own log; it must not travel into the event.
// class 是枚举化的原因。调用方把底层错误留在自己的日志里，
// 它绝不能进入事件。
func (r *Recorder) EmitBlock(ctx context.Context, tenant anonymize.Tenant, session string,
	class ErrorClass, entities map[string]int) {
	e := r.base(tenant, session, ActionBlock, OutcomeBlocked)
	e.ErrorClass = class
	e.Entities = copyCounts(entities)
	r.emit(ctx, e)
}

// EmitErasure records an Article 17 erasure with the counts that evidence it.
// 记录一次 GDPR 第 17 条擦除，并附上作为证据的条数。
func (r *Recorder) EmitErasure(ctx context.Context, tenant anonymize.Tenant,
	sessions, tokens int, class ErrorClass) {
	outcome := OutcomeOK
	if class != ErrNone {
		outcome = OutcomeFailed
	}
	e := r.base(tenant, "", ActionErase, outcome)
	e.SessionsErased = sessions
	e.TokensErased = tokens
	e.ErrorClass = class
	r.emit(ctx, e)
}

// base fills the fields every event shares.
// 填充所有事件共有的字段。
func (r *Recorder) base(tenant anonymize.Tenant, session string,
	action Action, outcome Outcome) Event {
	e := Event{
		Schema:    Schema,
		EventID:   NewEventID(),
		Timestamp: time.Now().UTC(),
		Tenant:    string(tenant),
		Action:    action,
		Outcome:   outcome,
	}
	if r.fp != nil && session != "" {
		// 指纹算不出来时留空，绝不退回原始会话 ID：
		// 那个回退正是这个字段存在的理由所要防的东西。
		// An unavailable fingerprint leaves the field empty; it never falls
		// back to the raw session id, which is the thing this field exists to
		// keep out.
		if fp, err := r.fp.Fingerprint(tenant, session); err == nil {
			e.SessionFingerprint = fp
		}
	}
	return e
}

// emit delivers the event, reporting sink failures without failing the request.
// 投递事件；sink 故障会上报，但不让请求失败。
func (r *Recorder) emit(ctx context.Context, e Event) {
	if err := r.sink.Emit(ctx, e); err != nil {
		r.onError(err)
	}
}

// countRecognizers tallies hits per recognizer.
// 按识别器统计命中数。
//
// A recognizer that has stopped firing is the shape a silent regression takes:
// nothing errors, the pipeline stays green, and the entity type it covered
// simply stops appearing. Per-rule counts in the trail make that visible from
// the SIEM before anyone notices the leak.
// 一条不再命中的识别器，正是静默回归的形态：不报错、管线照样全绿，
// 它覆盖的那类实体只是不再出现了。
// 轨迹里的逐规则计数让这件事能在 SIEM 里被看见——
// 在有人注意到那次泄露之前。
func countRecognizers(entities []detect.Entity) map[string]int {
	if len(entities) == 0 {
		return nil
	}
	out := make(map[string]int, len(entities))
	for _, e := range entities {
		if e.Detector == "" {
			continue
		}
		out[e.Detector]++
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// copyCounts returns a defensive copy so the event cannot change after emission.
// 返回防御性副本，使事件在发出后不会再被改动。
func copyCounts(in map[string]int) map[string]int {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
