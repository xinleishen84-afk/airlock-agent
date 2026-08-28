package eval

import "testing"

// skipPerfUnderRace 在竞态检测构建下跳过纯性能度量。
// Skips pure performance measurement under the race detector.
//
// # 为什么是跳过而不是放宽阈值
// # Why skip rather than loosen the thresholds
//
// -race 给每次内存访问插桩，实测拖慢 5~20 倍。这种构建下测出的吞吐与
// P99 描述的是竞态检测器，不是这个系统——放宽阈值只会得到一个两边都
// 不成立的数字：既拦不住真实回归，又不反映真实性能。
//
// 代价是明确的：CI 带 -race 跑，因此这些数字在 CI 上不再被验证。它们仍
// 在本地和不带 -race 的构建里跑。用「CI 上有一个自己都不信的数字」换
// 「CI 上没有这个数字」，后者更诚实。
//
// 实测触发点：eval 包在 CI 上带 -race 跑到 300 秒撞上超时，整包判失败，
// 而失败的是几个度量用例的耗时，不是任何一处正确性。
//
// The race detector instruments every memory access, measured 5-20x slower. A
// throughput or P99 figure from such a build describes the detector, not the
// system, and loosening thresholds only produces a number that is wrong in both
// directions: too slack to catch a real regression, too unrelated to describe
// real performance.
//
// The cost is explicit: CI runs with -race, so these numbers are no longer
// verified there. They still run locally and in non-race builds. Trading "a
// number in CI that nobody believes" for "no number in CI" is the honest trade.
//
// What forced this: the eval package hit the 300s timeout under -race in CI and
// failed as a whole — on the duration of measurement cases, not on any
// correctness assertion.
func skipPerfUnderRace(t *testing.T) {
	t.Helper()
	if raceEnabled {
		t.Skip("竞态检测下不做性能度量：插桩后的耗时描述的是检测器而非本系统")
	}
}
