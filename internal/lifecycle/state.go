// Package lifecycle 实现面向 SSE 长连接的三阶段优雅停机。
//
// # 为什么普通的 Shutdown 不够
//
// 普通 HTTP 服务的优雅停机只需 server.Shutdown(ctx)：关监听、等 Keep-Alive
// 连接回到空闲，几百毫秒就完事。LLM 网关不行，有两个原因：
//
//  1. **SSE 流可能持续数十秒**。暴力掐断正在吐字的连接，上游 Agent 会
//     收到一个截断的流——而它无法区分「生成完毕」与「被掐断」，
//     状态机直接破损。
//
//  2. **Shutdown 立刻关监听**。但 K8s 摘除 endpoint 有延迟（kube-proxy
//     同步 + LB 收敛，通常几秒）。这段窗口里新请求仍会打到本实例，
//     此时监听已关，客户端拿到的是 connection refused ——
//     比 503 糟得多：没有 Retry-After，也不会触发上游的重试策略。
//
// # 三阶段
//
//	SIGTERM
//	  │
//	  ├─ 阶段一 排空：/healthz 立刻翻 503，但**保持监听、照常服务**。
//	  │           给 K8s/LB 时间把本实例摘掉。
//	  │
//	  ├─ 阶段二 收敛：拒绝新请求（返回干净的 503 + Retry-After），
//	  │           等待在途 SSE 流自然结束。绝大多数生成在 15s 内完成。
//	  │
//	  └─ 阶段三 退出：持久化网关状态，物理关闭。
package lifecycle

import (
	"sync/atomic"
)

// Phase 是网关的生命周期阶段。
type Phase int32

const (
	// PhaseServing：正常服务
	PhaseServing Phase = iota
	// PhaseDraining：健康检查已翻 503，但仍接受并正常处理新请求。
	// 这一阶段存在的唯一目的是等 K8s 把本实例从 endpoint 里摘掉——
	// 此时拒绝请求反而会制造本可避免的错误。
	PhaseDraining
	// PhaseClosing：拒绝新请求，等待在途流收敛
	PhaseClosing
	// PhaseStopped：已停止
	PhaseStopped
)

// String 返回阶段名。
func (p Phase) String() string {
	switch p {
	case PhaseServing:
		return "serving"
	case PhaseDraining:
		return "draining"
	case PhaseClosing:
		return "closing"
	default:
		return "stopped"
	}
}

// State 是线程安全的生命周期状态。
//
// 用原子量而非互斥锁：每个请求都要读一次阶段，这是热路径，
// 锁竞争会直接体现在 TTFT 上。
type State struct {
	phase atomic.Int32
}

// NewState 创建处于服务中的状态。
func NewState() *State {
	s := &State{}
	s.phase.Store(int32(PhaseServing))
	return s
}

// Phase 返回当前阶段。
func (s *State) Phase() Phase { return Phase(s.phase.Load()) }

// Advance 推进到指定阶段。只允许单向推进，防止误调用把已停机的
// 实例又标回服务中——那会让 LB 重新把流量导进来。
func (s *State) Advance(p Phase) bool {
	for {
		cur := s.phase.Load()
		if int32(p) <= cur {
			return false
		}
		if s.phase.CompareAndSwap(cur, int32(p)) {
			return true
		}
	}
}

// Healthy 返回健康检查是否应报告健康。
//
// 一旦进入排空阶段就立刻返回 false——这是整个停机流程的起点，
// 也是唯一能让 K8s 主动摘除本实例的信号。
func (s *State) Healthy() bool { return s.Phase() == PhaseServing }

// AcceptingNew 返回是否还接受新请求。
//
// 排空阶段仍然接受：此时 LB 可能还没摘掉本实例，
// 拒绝会制造本可避免的错误。真正开始拒绝是在收敛阶段。
func (s *State) AcceptingNew() bool {
	p := s.Phase()
	return p == PhaseServing || p == PhaseDraining
}
