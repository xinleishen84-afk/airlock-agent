package integration

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/test/integration/chaos"
)

// 五项能力的合并验收。
//
// 每一项都必须在**真实网关进程**上、通过**外部可观测的证据**验证：
// 上游实际收到了什么、客户端实际收到了什么、时序是怎样的。
// 网关自己的日志与内部计数不作为证据——那正是「abandoned=0 静默通过」
// 那类问题的根源：用被测对象的自述来证明被测对象。

// nerService 是一个真实的 NER HTTP 服务。
type nerService struct {
	*httptest.Server
	known map[string]string
}

// startNER 启动 NER 服务。
func startNER(t *testing.T) *nerService {
	t.Helper()
	n := &nerService{known: map[string]string{
		"张伟": "NAME", "李娜": "NAME",
		"北京市朝阳区建国路88号": "ADDRESS",
		"星辰科技有限公司":     "ORG",
	}}
	n.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text  string   `json:"text"`
			Types []string `json:"types"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		type ent struct {
			Type       string  `json:"type"`
			Value      string  `json:"value"`
			Confidence float64 `json:"confidence"`
		}
		out := []ent{}
		for term, typ := range n.known {
			if strings.Contains(req.Text, term) {
				out = append(out, ent{Type: typ, Value: term, Confidence: 0.95})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"entities": out})
	}))
	t.Cleanup(n.Close)
	return n
}

// acceptanceConfig 生成验收用配置。
//
// Tier1 指向一个已关闭的地址：这样每个请求都必然触发失效转移，
// 把「多模型 Fallback」从偶发路径变成必经路径。
func acceptanceConfig(t *testing.T, deadTier1, liveTier2, nerURL string) string {
	t.Helper()
	dir := t.TempDir()
	secretDir := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "tier1-key"),
		[]byte("sk-ENTERPRISE-FROM-VAULT"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := fmt.Sprintf(`
secrets_mount_path: %s
targets:
  - name: tier1-cloud
    tier: 1
    base_url: %s
    model: premium-cloud
    credential_key: tier1-key
    input_price_per_mtok: 5.0
    output_price_per_mtok: 25.0
  - name: tier2-local
    tier: 2
    base_url: %s
    model: chaos
    self_hosted: true
rules:
  - name: planning-to-premium
    target_tier: 1
    priority: 10
    match_tasks: ["planning"]
rate_limit:
  tokens_per_window: 100000000
  window: 1m
pii:
  jurisdictions: [GEN, CN]
  session_consistency: single-replica
  fail_closed: true
  # 私有化后端默认不脱敏；验收要覆盖脱敏路径，故强制开启
  always_redact: true
  name_roster: ["王建国"]
  org_roster: ["星辰科技有限公司"]
  ner:
    endpoint: %s
    timeout: 2s
    types: ["NAME", "ADDRESS", "ORG"]
gpu:
  kv_elevated: 0.75
  kv_critical: 0.90
  prefix_affinity: true
  probe_interval: 500ms
`, secretDir, deadTier1, liveTier2, nerURL)

	path := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAcceptanceAllFiveCapabilities 在一次真实调用中验证全部五项能力。
func TestAcceptanceAllFiveCapabilities(t *testing.T) {
	// Tier1：启动后立刻关闭，制造确定的连接失败
	dead := chaos.Start(chaos.DefaultConfig())
	deadURL := dead.BaseURL()
	dead.Close()

	// Tier2：可用的慢流后端，速率调快以缩短验收耗时，
	// 但仍保留足够间隔以观测「逐帧到达」
	live := chaos.Start(chaos.Config{
		TokensPerSecond: 10, TotalTokens: 8,
		FirstTokenDelay: 50 * time.Millisecond, KVUsage: 0.3,
	})
	defer live.Close()

	ner := startNER(t)
	gw := startGateway(t,
		acceptanceConfig(t, deadURL, live.BaseURL(), ner.URL),
		"--log-level", "info")

	// 一次含 PII、含工具定义、走 Tier1 规则的流式请求
	reqBody := `{
	  "model": "premium-cloud",
	  "stream": true,
	  "max_tokens": 256,
	  "stop": ["<|end|>"],
	  "tools": [{
	    "type": "function",
	    "function": {
	      "name": "query_order",
	      "description": "按姓名查单，例如：张伟",
	      "parameters": {
	        "type": "object",
	        "properties": {
	          "city": {"type": "string", "enum": ["北京", "上海"],
	                   "description": "城市，如李娜所在的北京"}
	        },
	        "required": ["city"]
	      }
	    }
	  }],
	  "messages": [
	    {"role": "system", "content": "你是星辰科技有限公司助手，负责人王建国。"},
	    {"role": "user", "content": "客户张伟投诉，联系人李娜，手机 13812345678，地址北京市朝阳区建国路88号"}
	  ]
	}`

	start := time.Now()
	req, _ := http.NewRequest(http.MethodPost, gw.URL+"/v1/chat/completions",
		strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-DEVELOPER-PERSONAL-LEAKED")
	req.Header.Set("X-Workload-App", "planner-agent")
	req.Header.Set("X-Workload-Task", "planning")
	req.Header.Set("X-Session-Id", "acceptance-1")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v\n网关日志：\n%s", err, gw.Logs())
	}
	defer resp.Body.Close()

	// ═══ 能力一：高可用 —— Tier1 不可达时请求仍然成功 ═══
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Tier1 不可达时应转移到 Tier2 并成功，实际 HTTP %d：%s\n网关日志：\n%s",
			resp.StatusCode, body, gw.Logs())
	}

	// ═══ 能力二：流式 SSE ═══
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("应为 SSE 响应，实际 Content-Type=%q", ct)
	}
	if resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Error("缺少 X-Accel-Buffering: no——前置 nginx 会攒包，TTFT 照样是秒级")
	}

	type frame struct {
		at   time.Duration
		text string
	}
	var frames []frame
	var gotDone bool
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		payload, ok := strings.CutPrefix(strings.TrimSpace(line), "data: ")
		if !ok {
			continue
		}
		if payload == "[DONE]" {
			gotDone = true
			break
		}
		// 每一帧都必须是合法 JSON——复原若在裸文本上做替换，
		// 真实值含引号时这里就会解析失败
		var probe map[string]any
		if err := json.Unmarshal([]byte(payload), &probe); err != nil {
			t.Fatalf("响应帧不是合法 JSON（复原破坏了结构）：%s\n%v", payload, err)
		}
		var f struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		json.Unmarshal([]byte(payload), &f)
		if len(f.Choices) > 0 && f.Choices[0].Delta.Content != "" {
			frames = append(frames, frame{time.Since(start), f.Choices[0].Delta.Content})
		}
	}

	if !gotDone {
		t.Error("未收到 [DONE]，流未正常收尾")
	}
	if len(frames) < 3 {
		t.Fatalf("应收到多个增量帧，实际 %d 个", len(frames))
	}
	// 逐帧到达而非攒批：首帧应远早于末帧
	spread := frames[len(frames)-1].at - frames[0].at
	if spread < 200*time.Millisecond {
		t.Errorf("帧间总跨度仅 %v，数据被缓冲了——流式退化成了批式", spread)
	}
	t.Logf("流式：TTFT=%v，共 %d 帧，跨度 %v",
		frames[0].at.Round(time.Millisecond), len(frames), spread.Round(time.Millisecond))

	// ═══ 能力三：多模型 Fallback —— 转移确实发生 ═══
	metrics, err := scrapeMetrics(gw.URL)
	if err != nil {
		t.Fatalf("拉取指标失败: %v", err)
	}
	if live.Requests() == 0 {
		t.Error("Tier2 未收到任何请求——失效转移未发生")
	}
	if !strings.Contains(gw.Logs(), "已转移到备用后端") {
		t.Error("日志中未见转移记录")
	}
	t.Logf("失效转移：Tier2 收到 %d 个请求", live.Requests())

	// ═══ 能力四：PII 双向脱敏 ═══
	outbound := live.LastBody()
	if outbound == "" {
		t.Fatal("上游未记录到请求体")
	}
	// 出境侧：真实 PII 绝不出现
	for _, secret := range []string{
		"张伟", "李娜", "王建国", "星辰科技有限公司",
		"13812345678", "北京市朝阳区建国路88号",
	} {
		if strings.Contains(outbound, secret) {
			t.Errorf("真实 PII %q 越过了企业边界：\n%s", secret, outbound)
		}
	}
	if !strings.Contains(outbound, "ANONYMIZED_") {
		t.Errorf("出境载荷中未见占位符，脱敏可能未生效：\n%s", outbound)
	}
	// 入境侧：占位符被还原为真实值
	joined := ""
	for _, f := range frames {
		joined += f.text
	}
	if strings.Contains(joined, "ANONYMIZED_") {
		t.Errorf("响应中残留未复原的占位符：%s", joined)
	}

	// ═══ 能力五：白名单锁死协议污染 ═══
	var sent map[string]any
	if err := json.Unmarshal([]byte(outbound), &sent); err != nil {
		t.Fatalf("出境载荷不是合法 JSON：%v\n%s", err, outbound)
	}
	assertPath := func(want any, path ...any) {
		t.Helper()
		cur := any(sent)
		for _, p := range path {
			switch k := p.(type) {
			case string:
				m, ok := cur.(map[string]any)
				if !ok {
					t.Fatalf("路径 %v 处不是对象", path)
				}
				cur = m[k]
			case int:
				a, ok := cur.([]any)
				if !ok || k >= len(a) {
					t.Fatalf("路径 %v 处不是数组或越界", path)
				}
				cur = a[k]
			}
		}
		if cur != want {
			t.Errorf("协议骨架 %v 被污染：期望 %v，实际 %v", path, want, cur)
		}
	}
	// 出境字节里不应出现 HTML 转义。网关的职责是转发，不该无故改写
	// 用户内容——含大量 <> 的代码或停止序列会从 1 字节膨胀到 6 字节。
	// 注意：这里必须查**原始字节**，用 json.Marshal 再打印会重新引入转义，
	// 把网关的正确行为掩盖掉。
	if strings.Contains(outbound, `\u003c`) || strings.Contains(outbound, `\u003e`) {
		t.Errorf("出境载荷含 HTML 转义，网关改写了用户内容的字节：\n%s", outbound)
	}
	if !strings.Contains(outbound, "<|end|>") {
		t.Errorf("停止序列未按原样透传：\n%s", outbound)
	}

	assertPath("premium-cloud", "model")
	assertPath("<|end|>", "stop", 0)
	assertPath("system", "messages", 0, "role")
	assertPath("user", "messages", 1, "role")
	assertPath("function", "tools", 0, "type")
	assertPath("query_order", "tools", 0, "function", "name")
	assertPath("北京", "tools", 0, "function", "parameters", "properties", "city", "enum", 0)
	assertPath("上海", "tools", 0, "function", "parameters", "properties", "city", "enum", 1)
	assertPath("string", "tools", 0, "function", "parameters", "properties", "city", "type")
	assertPath("city", "tools", 0, "function", "parameters", "required", 0)

	// 而自然语言区域确实被净化了
	desc, _ := digString(sent, "tools", 0, "function", "description")
	if strings.Contains(desc, "张伟") {
		t.Errorf("工具描述中的示例 PII 未脱敏：%q", desc)
	}
	schemaDesc, _ := digString(sent, "tools", 0, "function",
		"parameters", "properties", "city", "description")
	if strings.Contains(schemaDesc, "李娜") {
		t.Errorf("schema 描述中的示例 PII 未脱敏：%q", schemaDesc)
	}

	// ═══ 附带：零信任凭证 ═══
	if strings.Contains(gw.Logs(), "sk-DEVELOPER-PERSONAL-LEAKED") {
		t.Error("客户端自携凭证出现在网关日志中")
	}

	// 打印原始字节而非重新序列化：prettyJSON 会用 json.Marshal
	// 重新引入 HTML 转义，让人误以为网关做了转义
	t.Logf("出境载荷原始字节（云端厂商实际所见）：\n  %s", outbound)
	_ = metrics
}

// digString 按路径取字符串值。
func digString(doc any, path ...any) (string, bool) {
	cur := doc
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return "", false
			}
			cur = m[k]
		case int:
			a, ok := cur.([]any)
			if !ok || k >= len(a) {
				return "", false
			}
			cur = a[k]
		}
	}
	s, ok := cur.(string)
	return s, ok
}

// prettyJSON 格式化 JSON 便于阅读。
func prettyJSON(raw string) string {
	var v any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return raw
	}
	out, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		return raw
	}
	return "  " + string(out)
}
