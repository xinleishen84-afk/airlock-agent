package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// # 二进制的能力自陈必须与它的实际行为一致
// # A binary's claimed capabilities must match what it does
//
// 这个文件针对一类已经出现过三次的故障：**声明在一处、实现在另一处、
// 测量在第三处，三者各说各的，而没有任何东西把它们对起来。**
//
// This targets a failure that has occurred three times: declared in one place,
// implemented in another, measured in a third, with nothing connecting them.
//
//  1. 证据链验证器在每一个单元测试里都接着，在真实二进制里从来没接上。
//     后果：模型给出的「上海市」与「浦东」被当成两个独立地址各自脱敏，
//     「新区世纪大道100号」原样出境——而 entity_counts 显示 ADDRESS:2，
//     看起来比正确答案还多检出一个。
//
//  2. Core 二进制的启动日志声称覆盖「静态名册与复姓」，而它根本没装配
//     复姓识别器。
//
//  3. README 里 Core 模式的 90.5% 覆盖率，量的是带复姓的配置——
//     那个数字描述的不是这个二进制。
//
// 三次都不是逻辑写错，是装配漏了。单元测试全绿，因为它们各自装配自己的
// 那一份。只有把真实二进制跑起来、按它自己声称的能力去拨测，才能发现。
//
// None of the three was a logic error; all three were assembly omissions. The
// unit tests were green because each assembles its own copy. Only running the
// real binary and probing it against its own claims finds them.

// binaryUnderTest 构建并启动一个命令，返回它的监听地址。
//
// 按名字取命令而不是按路径：路径写死会随改名烂掉，而名字不存在时
// CommandNamed 会立刻报错并列出仓库里现有的全部命令。
//
// Looked up by name rather than path: a hardcoded path rots on rename, while
// an unknown name fails immediately with the available set.
func binaryUnderTest(t *testing.T, name string, args ...string) string {
	t.Helper()

	bin := CommandNamed(t, name).Build(t)
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	cmd := exec.Command(bin, append([]string{"--addr", addr}, args...)...)
	var logs bytes.Buffer
	cmd.Stderr = &logs
	cmd.Stdout = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("被测二进制日志：\n%s", logs.String())
		}
	})

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			return addr
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("二进制未在 30s 内就绪\n%s", logs.String())
	return ""
}

type redactResult struct {
	Text         string         `json:"text"`
	EntityCounts map[string]int `json:"entity_counts"`
	Blocked      bool           `json:"blocked"`
}

func redactVia(t *testing.T, addr, tenant, text string) redactResult {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"session_id": "cap-test", "text": text})
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/redact", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if tenant != "" {
		req.Header.Set("X-Tenant-Id", tenant)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var out redactResult
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("响应不是合法 JSON（%d）：%s", resp.StatusCode, raw)
	}
	return out
}

// Core 二进制声称覆盖复姓 —— 拨测它是否真的覆盖。
// The Core binary claims compound-surname coverage; probe whether it does.
func TestCoreBinaryCoversWhatItClaims(t *testing.T) {
	addr := binaryUnderTest(t, "airlock-agent",
		"--jurisdictions", "GEN,CN", "--single-tenant", "acme")

	cases := []struct{ name, text, want string }{
		{"校验位", "身份证 11010519491231002X", "11010519491231002X"},
		{"Luhn+IIN", "卡号 4111111111111111", "4111111111111111"},
		{"正则", "手机 13812345678", "13812345678"},
		{"复姓", "经办人欧阳志远已签字", "欧阳志远"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := redactVia(t, addr, "acme", c.text)
			if strings.Contains(res.Text, c.want) {
				t.Errorf("Core 声称覆盖%s，但 %q 原样出现在输出里：%s",
					c.name, c.want, res.Text)
			}
		})
	}
}

// Core 二进制必须接上证据链 —— 否则复姓候选会带来误报。
// Core must have the evidence chain, or surname candidates bring false
// positives.
//
// 复姓识别产出的是候选不是判决。把它加进 Core 而不同时加证据链，
// 是把召回换成了误报。这条用例同时钉住两件事：复姓在、证据链也在。
func TestCoreBinaryHasEvidenceChain(t *testing.T) {
	addr := binaryUnderTest(t, "airlock-agent",
		"--jurisdictions", "GEN,CN", "--single-tenant", "acme",
		"--single-surnames") // 故意开启单姓，把误报压力拉满

	// 这些是「像人名但不是」的中文，证据链应当把它们挡下
	for _, text := range []string{
		"王者荣耀的新赛季已经开启。",
		"李子和杨梅都是夏季水果。",
		"黄河与长江是中国的两条大河。",
	} {
		t.Run(text[:9], func(t *testing.T) {
			res := redactVia(t, addr, "acme", text)
			if n := res.EntityCounts["NAME"]; n > 0 {
				t.Errorf("证据链未生效：%q 被判出 %d 个人名\n输出：%s",
					text, n, res.Text)
			}
		})
	}
}

// 二进制的启动自陈必须与它的装配一致。
// The startup self-report must match what was assembled.
//
// 「运行在 Core 模式 覆盖=…静态名册与复姓」这句话曾经是假的：
// 复姓识别器根本没被装配。日志说了什么，就必须能被拨测验证。
func TestCoreStartupClaimIsProbeable(t *testing.T) {
	bin := CommandNamed(t, "airlock-agent").Build(t)

	port := freePort(t)
	cmd := exec.Command(bin, "--addr", fmt.Sprintf("127.0.0.1:%d", port),
		"--jurisdictions", "GEN,CN", "--single-tenant", "acme")
	var logs bytes.Buffer
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()

	out := logs.String()
	for _, claim := range []string{"Core 模式", "复姓", "证据链已装配"} {
		if !strings.Contains(out, claim) {
			t.Errorf("启动日志里没有声明 %q —— 而它是这个二进制应有的能力\n%s",
				claim, out)
		}
	}
	t.Logf("启动自陈：\n%s", out)
}
