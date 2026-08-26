package gpuload

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// vllmMetrics 生成一份形似 vLLM 的指标输出。
func vllmMetrics(running, waiting int, kv float64, preemptions int) string {
	return fmt.Sprintf(`# HELP vllm:num_requests_running Number of requests currently running.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{model_name="gpt-oss-120b"} %d.0
vllm:num_requests_waiting{model_name="gpt-oss-120b"} %d.0
vllm:gpu_cache_usage_perc{model_name="gpt-oss-120b"} %f
vllm:prefix_cache_queries_total{model_name="gpt-oss-120b"} 1000.0
vllm:prefix_cache_hits_total{model_name="gpt-oss-120b"} 850.0
vllm:num_preemptions_total{model_name="gpt-oss-120b"} %d.0
`, running, waiting, kv, preemptions)
}

// TestParsePrometheus 校验指标解析，含带 label 与不带 label 两种形态。
func TestParsePrometheus(t *testing.T) {
	s, err := ParsePrometheus(strings.NewReader(vllmMetrics(12, 5, 0.62, 0)))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if s.Running != 12 || s.Waiting != 5 {
		t.Errorf("请求数解析错误: %+v", s)
	}
	if s.KVCacheUsage < 0.619 || s.KVCacheUsage > 0.621 {
		t.Errorf("KV 占用解析错误: %f", s.KVCacheUsage)
	}
	if hit := s.PrefixHitRate(); hit < 0.849 || hit > 0.851 {
		t.Errorf("前缀命中率计算错误: %f", hit)
	}
}

// TestParseWithoutLabels 校验无 label 形态也能解析。
func TestParseWithoutLabels(t *testing.T) {
	raw := "vllm:num_requests_running 3\nvllm:num_requests_waiting 1\nvllm:gpu_cache_usage_perc 0.5\n"
	s, err := ParsePrometheus(strings.NewReader(raw))
	if err != nil || s.Running != 3 || s.KVCacheUsage != 0.5 {
		t.Errorf("无 label 解析失败: %+v err=%v", s, err)
	}
}

// TestParseIncompleteRejected 校验残缺指标被拒。
//
// 基于残缺数据做准入判断比没有数据更危险——它看起来是有效的，
// 会让网关在 KV 已满时继续放行。
func TestParseIncompleteRejected(t *testing.T) {
	raw := "vllm:num_requests_running 3\n# 其余指标缺失\n"
	if _, err := ParsePrometheus(strings.NewReader(raw)); err == nil {
		t.Error("残缺指标应报错而非返回部分快照")
	}
}

// TestPressureLevels 校验压力分档。
func TestPressureLevels(t *testing.T) {
	th := DefaultThresholds()
	cases := []struct {
		desc string
		snap Snapshot
		want Pressure
	}{
		{"空闲", Snapshot{Valid: true, KVCacheUsage: 0.20, Waiting: 0}, PressureNormal},
		{"KV 吃紧", Snapshot{Valid: true, KVCacheUsage: 0.80, Waiting: 0}, PressureElevated},
		{"KV 濒临", Snapshot{Valid: true, KVCacheUsage: 0.95, Waiting: 0}, PressureCritical},
		{"队列堆积", Snapshot{Valid: true, KVCacheUsage: 0.30, Waiting: 10}, PressureElevated},
		{"队列爆炸", Snapshot{Valid: true, KVCacheUsage: 0.30, Waiting: 50}, PressureCritical},
		{"采样无效", Snapshot{Valid: false}, PressureUnknown},
	}
	for _, c := range cases {
		st := NewState("b", th)
		st.Update(c.snap)
		if got := st.Pressure(); got != c.want {
			t.Errorf("%s: 压力等级 %s，期望 %s", c.desc, got, c.want)
		}
	}
}

// TestPreemptionForcesCritical 校验抢占一票否决。
//
// 抢占意味着 KV 已经不够用，后端在反复换出重算。此时 KV 占用读数
// 可能反而下降（换出腾出了空间），只看占用率会误判为「好转」，
// 继续放行则加剧活锁。
func TestPreemptionForcesCritical(t *testing.T) {
	st := NewState("b", DefaultThresholds())
	st.Update(Snapshot{Valid: true, KVCacheUsage: 0.50, Preemptions: 0})
	if st.Pressure() != PressureNormal {
		t.Fatal("初始应为 normal")
	}

	// 抢占计数增长，但 KV 占用反而下降——换出腾出了空间
	st.Update(Snapshot{Valid: true, KVCacheUsage: 0.40, Preemptions: 3})
	if st.Pressure() != PressureCritical {
		t.Errorf("抢占发生时必须判定 critical，实际 %s", st.Pressure())
	}
}

// TestStaleSnapshotBecomesUnknown 校验陈旧快照转为 Unknown。
// 探测挂掉后沿用旧数据，等于闭眼开车。
func TestStaleSnapshotBecomesUnknown(t *testing.T) {
	th := DefaultThresholds()
	th.StaleAfter = 20 * time.Millisecond
	st := NewState("b", th)
	st.Update(Snapshot{Valid: true, KVCacheUsage: 0.1})

	time.Sleep(40 * time.Millisecond)
	// 压力值缓存在原子量里，需重新触发计算
	st.Update(st.Snapshot())
	// 重新 Update 会刷新 updatedAt，因此改为直接验证陈旧判定逻辑
	st2 := NewState("b2", th)
	st2.Update(Snapshot{Valid: true, KVCacheUsage: 0.1})
	time.Sleep(40 * time.Millisecond)
	st2.mu.RLock()
	p := st2.computeLocked()
	st2.mu.RUnlock()
	if p != PressureUnknown {
		t.Errorf("陈旧快照应判定为 unknown，实际 %s", p)
	}
}

// TestGradedDegradation 校验按优先级分档降级。
//
// 核心思想：在 GPU 死锁之前先牺牲低价值流量。等完全打满再一刀切拒绝，
// 队列里已经全是低优先级请求，高价值请求照样排在后面。
func TestGradedDegradation(t *testing.T) {
	st := NewState("b", DefaultThresholds())

	st.Update(Snapshot{Valid: true, KVCacheUsage: 0.80}) // Elevated
	if d := st.Admit(2); d.Admit {
		t.Error("Elevated 下低优先级（批量作业）应被拒")
	}
	if d := st.Admit(5); !d.Admit {
		t.Error("Elevated 下中等优先级应放行")
	}

	st.Update(Snapshot{Valid: true, KVCacheUsage: 0.95}) // Critical
	if d := st.Admit(5); d.Admit {
		t.Error("Critical 下中等优先级应被拒")
	}
	if d := st.Admit(9); !d.Admit {
		t.Error("Critical 下最高优先级仍应放行")
	}
}

// TestRetryAfterScalesWithPressure 校验重试建议随压力递增。
// Critical 时给长退避，避免重试风暴把刚腾出的 KV 又填满。
func TestRetryAfterScalesWithPressure(t *testing.T) {
	st := NewState("b", DefaultThresholds())
	st.Update(Snapshot{Valid: true, KVCacheUsage: 0.80})
	elevated := st.Admit(1).RetryAfter
	st.Update(Snapshot{Valid: true, KVCacheUsage: 0.95})
	critical := st.Admit(1).RetryAfter

	if critical <= elevated {
		t.Errorf("Critical 的退避应长于 Elevated：%v vs %v", critical, elevated)
	}
}

// TestUnknownIsConservativeNotFatal 校验探测失效时折中处理。
//
// 完全拒绝会把探测故障升级成服务故障，完全放行则失去保护。
func TestUnknownIsConservativeNotFatal(t *testing.T) {
	st := NewState("b", DefaultThresholds())
	if st.Pressure() != PressureUnknown {
		t.Fatal("未探测过时应为 unknown")
	}
	if st.Admit(2).Admit {
		t.Error("探测失效时应拒绝低优先级")
	}
	if !st.Admit(6).Admit {
		t.Error("探测失效时不应连中高优先级一起拒——那会把探测故障升级成服务故障")
	}
}

// TestProbeUpdatesState 校验探针端到端拉取并更新状态。
func TestProbeUpdatesState(t *testing.T) {
	var kv atomic.Value
	kv.Store(0.30)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, vllmMetrics(5, 2, kv.Load().(float64), 0))
	}))
	defer srv.Close()

	reg := NewRegistry()
	reg.Register("b1", DefaultThresholds())
	probe := NewProbe(reg, []Target{{Name: "b1", MetricsURL: srv.URL + "/metrics"}},
		10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))

	stop := probe.Start(context.Background())
	defer stop()

	if got := reg.Get("b1").Pressure(); got != PressureNormal {
		t.Fatalf("首次探测后应为 normal，实际 %s", got)
	}

	kv.Store(0.95)
	deadline := time.After(2 * time.Second)
	for reg.Get("b1").Pressure() != PressureCritical {
		select {
		case <-deadline:
			t.Fatalf("KV 升至 95%% 后压力等级未跟进，仍为 %s", reg.Get("b1").Pressure())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestProbeFailureYieldsUnknown 校验探测失败时状态转为 Unknown 而非沿用旧值。
func TestProbeFailureYieldsUnknown(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		io.WriteString(w, vllmMetrics(1, 0, 0.1, 0))
	}))
	defer srv.Close()

	reg := NewRegistry()
	reg.Register("b1", DefaultThresholds())
	probe := NewProbe(reg, []Target{{Name: "b1", MetricsURL: srv.URL + "/metrics"}},
		10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	stop := probe.Start(context.Background())
	defer stop()

	if reg.Get("b1").Pressure() != PressureNormal {
		t.Fatal("健康时应为 normal")
	}

	healthy.Store(false)
	deadline := time.After(2 * time.Second)
	for reg.Get("b1").Pressure() != PressureUnknown {
		select {
		case <-deadline:
			t.Fatal("探测失败后应转为 unknown，不能沉默沿用旧数据")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestMetricsURLStripsV1 校验 /v1 后缀被正确剥离。
//
// 不处理这个细节会导致所有探测 404，表现为「压力永远 Unknown」，
// 很难一眼看出原因。
func TestMetricsURLFor(t *testing.T) {
	cases := map[string]string{
		"http://gpu:8000/v1":  "http://gpu:8000/metrics",
		"http://gpu:8000/v1/": "http://gpu:8000/metrics",
		"http://gpu:8000":     "http://gpu:8000/metrics",
	}
	for in, want := range cases {
		if got := MetricsURLFor(in); got != want {
			t.Errorf("MetricsURLFor(%q) = %q，期望 %q", in, got, want)
		}
	}
}
