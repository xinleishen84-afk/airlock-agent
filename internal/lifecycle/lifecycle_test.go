package lifecycle

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 状态机
// ---------------------------------------------------------------------------

// TestPhaseAdvancesOneWay 校验阶段只能单向推进。
//
// 若允许回退，一个误调用就能把已停机的实例标回「服务中」，
// LB 会重新把流量导进来——而此时在途流已经被中断，进程正准备退出。
func TestPhaseAdvancesOneWay(t *testing.T) {
	s := NewState()
	if !s.Advance(PhaseDraining) || s.Phase() != PhaseDraining {
		t.Fatal("应能推进到排空阶段")
	}
	if s.Advance(PhaseServing) {
		t.Error("不应允许回退到服务中")
	}
	if s.Phase() != PhaseDraining {
		t.Errorf("阶段被回退了：%s", s.Phase())
	}
	if s.Advance(PhaseDraining) {
		t.Error("重复推进到同一阶段应返回 false")
	}
}

// TestHealthFlipsImmediately 校验进入排空阶段后健康检查立刻翻 503。
// 这是唯一能让 K8s 主动摘除本实例的信号。
func TestHealthFlipsImmediately(t *testing.T) {
	s := NewState()
	srv := httptest.NewServer(HealthHandler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("服务中应返回 200，实际 %d", resp.StatusCode)
	}

	s.Advance(PhaseDraining)
	resp, err = http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("排空阶段应返回 503，实际 %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Gateway-Phase") != "draining" {
		t.Errorf("应在头部暴露当前阶段：%q", resp.Header.Get("X-Gateway-Phase"))
	}
}

// TestDrainingStillAcceptsNew 校验排空阶段仍接受新请求。
//
// 此时 LB 大概率还没摘掉本实例，拒绝会制造本可避免的错误。
// 真正开始拒绝是在收敛阶段。
func TestDrainingStillAcceptsNew(t *testing.T) {
	s := NewState()
	s.Advance(PhaseDraining)
	if !s.AcceptingNew() {
		t.Error("排空阶段必须继续接受新请求——否则会在 LB 摘除生效前制造错误")
	}
	if s.Healthy() {
		t.Error("排空阶段健康检查必须已翻 503")
	}

	s.Advance(PhaseClosing)
	if s.AcceptingNew() {
		t.Error("收敛阶段应拒绝新请求")
	}
}

// ---------------------------------------------------------------------------
// 在途跟踪
// ---------------------------------------------------------------------------

// TestTrackerCounts 校验流式与非流式分开计数。
func TestTrackerCounts(t *testing.T) {
	tr := NewTracker()
	doneA := tr.Enter(true)  // 流式
	doneB := tr.Enter(false) // 非流式

	if tr.InFlight() != 2 || tr.Streaming() != 1 {
		t.Errorf("计数错误：in_flight=%d streaming=%d", tr.InFlight(), tr.Streaming())
	}
	doneA()
	if tr.Streaming() != 0 || tr.InFlight() != 1 {
		t.Errorf("流式结束后计数错误：in_flight=%d streaming=%d", tr.InFlight(), tr.Streaming())
	}
	doneB()
	if tr.InFlight() != 0 {
		t.Errorf("全部结束后应归零，实际 %d", tr.InFlight())
	}
}

// TestTrackerDoneIsIdempotent 校验重复调用 Done 不会让计数变负。
// 计数变负会让 WaitZero 永远等不到归零信号。
func TestTrackerDoneIsIdempotent(t *testing.T) {
	tr := NewTracker()
	done := tr.Enter(true)
	done()
	done()
	done()
	if tr.InFlight() != 0 || tr.Streaming() != 0 {
		t.Errorf("重复调用应幂等，实际 in_flight=%d streaming=%d",
			tr.InFlight(), tr.Streaming())
	}
}

// TestWaitZeroReturnsOnDrain 校验在途归零时立刻返回。
func TestWaitZeroReturnsOnDrain(t *testing.T) {
	tr := NewTracker()
	done := tr.Enter(true)

	go func() {
		time.Sleep(30 * time.Millisecond)
		done()
	}()

	start := time.Now()
	if !tr.WaitZero(context.Background(), 5*time.Second) {
		t.Fatal("归零后应返回 true")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("应在归零后立刻返回，实际等了 %v", elapsed)
	}
}

// TestWaitZeroTimesOut 校验超时返回 false。
func TestWaitZeroTimesOut(t *testing.T) {
	tr := NewTracker()
	defer tr.Enter(true)() // 故意不结束

	if tr.WaitZero(context.Background(), 50*time.Millisecond) {
		t.Error("有在途请求时超时应返回 false")
	}
}

// TestWaitZeroWhenAlreadyEmpty 校验无在途时立刻返回。
func TestWaitZeroWhenAlreadyEmpty(t *testing.T) {
	tr := NewTracker()
	start := time.Now()
	if !tr.WaitZero(context.Background(), 5*time.Second) {
		t.Error("无在途时应立刻返回 true")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Error("不应等待")
	}
}

// TestTrackerConcurrent 校验并发下的计数正确性。
func TestTrackerConcurrent(t *testing.T) {
	tr := NewTracker()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				done := tr.Enter(n%2 == 0)
				done()
			}
		}(i)
	}
	wg.Wait()
	if tr.InFlight() != 0 || tr.Streaming() != 0 {
		t.Errorf("并发后应归零，实际 in_flight=%d streaming=%d",
			tr.InFlight(), tr.Streaming())
	}
}

// ---------------------------------------------------------------------------
// 三阶段编排
// ---------------------------------------------------------------------------

// fastOptions 是加速版的停机窗口，用于测试。
func fastOptions() ShutdownOptions {
	return ShutdownOptions{
		DrainPeriod:  30 * time.Millisecond,
		GracePeriod:  200 * time.Millisecond,
		ForceTimeout: 50 * time.Millisecond,
		PollInterval: 20 * time.Millisecond,
	}
}

// TestShutdownPhaseOrder 校验三阶段严格按序发生。
//
// 顺序错了后果很具体：先关监听再翻健康检查，那段窗口里的请求
// 会拿到 connection refused 而不是 503。
func TestShutdownPhaseOrder(t *testing.T) {
	state := NewState()
	tr := NewTracker()

	var mu sync.Mutex
	var phases []Phase
	sd := &Shutdowner{
		State: state, Tracker: tr, Options: fastOptions(),
		OnPhase: func(p Phase) {
			mu.Lock()
			phases = append(phases, p)
			mu.Unlock()
		},
	}
	sd.Run(context.Background())

	mu.Lock()
	defer mu.Unlock()
	want := []Phase{PhaseDraining, PhaseClosing, PhaseStopped}
	if len(phases) != len(want) {
		t.Fatalf("阶段数不符：%v", phases)
	}
	for i, p := range want {
		if phases[i] != p {
			t.Errorf("第 %d 阶段应为 %s，实际 %s", i+1, p, phases[i])
		}
	}
}

// TestShutdownWaitsForActiveStream 校验在途流被等待而非掐断。
//
// 这是整个三阶段设计的核心目的：暴力掐断正在吐字的 SSE，
// 上游 Agent 无法区分「生成完毕」与「被截断」，状态机直接破损。
func TestShutdownWaitsForActiveStream(t *testing.T) {
	state := NewState()
	tr := NewTracker()
	done := tr.Enter(true)

	streamFinished := make(chan struct{})
	go func() {
		// 模拟一条还在吐字的流，在宽限期内结束
		time.Sleep(100 * time.Millisecond)
		done()
		close(streamFinished)
	}()

	sd := &Shutdowner{State: state, Tracker: tr, Options: fastOptions()}
	res := sd.Run(context.Background())

	select {
	case <-streamFinished:
	default:
		t.Fatal("停机不应早于在途流结束")
	}
	if !res.Graceful {
		t.Errorf("在途流按时结束时应判定为优雅停机：%+v", res)
	}
	if res.Abandoned != 0 {
		t.Errorf("不应有被中断的连接，实际 %d", res.Abandoned)
	}
}

// TestShutdownReportsAbandoned 校验超时未结束的连接被如实统计。
//
// 这个数字是评估宽限期是否合理的唯一依据。持续偏高就说明
// grace_period 短于典型生成时长，必须调大——而不是假装没发生。
func TestShutdownReportsAbandoned(t *testing.T) {
	state := NewState()
	tr := NewTracker()
	defer tr.Enter(true)() // 永不结束的流
	defer tr.Enter(true)()

	sd := &Shutdowner{State: state, Tracker: tr, Options: fastOptions()}
	res := sd.Run(context.Background())

	if res.Graceful {
		t.Error("有连接被强制中断时不应报告为优雅停机")
	}
	if res.Abandoned != 2 {
		t.Errorf("应统计出 2 条被中断的连接，实际 %d", res.Abandoned)
	}
}

// TestShutdownRejectsNewDuringClosing 校验收敛阶段拒绝新请求。
func TestShutdownRejectsNewDuringClosing(t *testing.T) {
	state := NewState()
	tr := NewTracker()
	defer tr.Enter(true)()

	acceptDuringDrain := make(chan bool, 1)
	go func() {
		// 排空期中段采样：此时应仍接受新请求
		time.Sleep(15 * time.Millisecond)
		acceptDuringDrain <- state.AcceptingNew()
	}()

	sd := &Shutdowner{State: state, Tracker: tr, Options: fastOptions()}
	sd.Run(context.Background())

	if !<-acceptDuringDrain {
		t.Error("排空阶段应仍接受新请求")
	}
	if state.AcceptingNew() {
		t.Error("停机结束后不应再接受新请求")
	}
}

// TestShutdownPersistsState 校验阶段三持久化状态。
func TestShutdownPersistsState(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(filepath.Join(dir, "state.json"))

	sd := &Shutdowner{
		State: NewState(), Tracker: NewTracker(),
		Store: store, Options: fastOptions(),
		Collect: func() *Snapshot {
			return &Snapshot{
				BudgetSpent:   map[string]float64{"1": 480.25},
				RateLimitUsed: map[string]int64{"acme/bot": 12345},
			}
		},
	}
	res := sd.Run(context.Background())
	if !res.StateSaved {
		t.Fatal("状态应被持久化")
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if loaded.BudgetSpent["1"] != 480.25 {
		t.Errorf("预算未正确保存：%v", loaded.BudgetSpent)
	}
	if loaded.RateLimitUsed["acme/bot"] != 12345 {
		t.Errorf("限流用量未正确保存：%v", loaded.RateLimitUsed)
	}
}

// TestValidateRejectsZeroGrace 校验宽限期为 0 被拒。
func TestValidateRejectsZeroGrace(t *testing.T) {
	o := DefaultShutdownOptions()
	o.GracePeriod = 0
	if err := o.Validate(); err == nil {
		t.Error("宽限期为 0 等于暴力掐断，应被拒绝")
	}
}

// ---------------------------------------------------------------------------
// 快照
// ---------------------------------------------------------------------------

// TestSnapshotNeverContainsPII 是本文件最重要的断言。
//
// 快照会落盘、会被备份、可能被运维查看。它一旦装进 PII 脱敏映射，
// 脱敏网关就变成了 PII 数据库——一次备份泄露，整条防线全废。
//
// 这里从数据模型层面确认：Snapshot 结构体里没有任何字段能装下
// 「占位符 -> 真实值」的映射。
func TestSnapshotNeverContainsPII(t *testing.T) {
	snap := &Snapshot{
		BudgetSpent:   map[string]float64{"1": 100},
		RateLimitUsed: map[string]int64{"acme/toolbench-agent": 500},
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}

	// 结构上只允许数字型的值。任何 string->string 的映射字段
	// 都可能被用来装 PII，必须在评审时被拦下
	var probe map[string]any
	json.Unmarshal(raw, &probe)
	for key, val := range probe {
		switch key {
		case "version", "saved_at", "instance_id":
			continue
		}
		m, ok := val.(map[string]any)
		if !ok {
			continue
		}
		for k, v := range m {
			if _, isString := v.(string); isString {
				t.Errorf("快照字段 %s.%s 是字符串值——"+
					"这类字段可能被用来装 PII，快照只应保存计量数字", key, k)
			}
		}
	}
}

// TestFileStoreAtomicWrite 校验写入是原子的。
//
// 停机时进程随时可能被 SIGKILL（K8s 的 terminationGracePeriod 到点）。
// 直接覆写会留下半截文件，下次启动加载时预算数据就是错的。
func TestFileStoreAtomicWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewFileStore(path)

	if err := store.Save(&Snapshot{BudgetSpent: map[string]float64{"1": 1}}); err != nil {
		t.Fatal(err)
	}
	// 临时文件不应残留
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("临时文件应已被 rename 掉")
	}
	if err := store.Save(&Snapshot{BudgetSpent: map[string]float64{"1": 2}}); err != nil {
		t.Fatal(err)
	}
	loaded, _ := store.Load()
	if loaded.BudgetSpent["1"] != 2 {
		t.Errorf("覆写后应是新值：%v", loaded.BudgetSpent)
	}
}

// TestFileStoreMissingIsNotError 校验首次启动（无快照）不是错误。
func TestFileStoreMissingIsNotError(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "absent.json"))
	snap, err := store.Load()
	if err != nil {
		t.Errorf("首次启动不应报错: %v", err)
	}
	if snap != nil {
		t.Error("无快照时应返回 nil")
	}
}

// TestFileStoreRejectsVersionMismatch 校验版本不符时拒绝加载。
//
// 按字段缺失静默降级会让预算被悄悄清零，且没有任何迹象。
func TestFileStoreRejectsVersionMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.json")
	os.WriteFile(path, []byte(`{"version":999,"budget_spent":{"1":100}}`), 0o600)

	if _, err := NewFileStore(path).Load(); err == nil {
		t.Error("版本不符应拒绝加载，而非静默降级")
	} else if !strings.Contains(err.Error(), "版本") {
		t.Errorf("报错应说明是版本问题：%v", err)
	}
}
