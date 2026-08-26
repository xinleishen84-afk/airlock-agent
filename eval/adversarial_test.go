package eval

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// 上面那些误报是被语料抓到后修掉的，所以语料本身已经不再能证明什么了。
// 这一组用生成的、没人调过的输入重新量一遍。
//
// The false positives above were fixed after the corpus caught them, so the
// corpus no longer proves anything. This measures again on generated input
// nobody tuned against.

// 随机数字串被误报为卡号的比例。
// The rate at which random digit runs are reported as card numbers.
//
// 只用 Luhn 时这个比例约为 1/10（单位校验位的理论值）。
// 加上 ISO/IEC 7812 的 IIN 前缀与各卡组织实际签发的长度之后，它应当低得多。
// With Luhn alone this is about 1 in 10 — what a single check digit predicts.
func TestFalseCardRateOnRandomDigits(t *testing.T) {
	d := rosterDetector(t)
	rng := rand.New(rand.NewPCG(42, 1))

	const trials = 20000
	luhnOnly, full := 0, 0

	for range trials {
		n := 12 + rng.IntN(8) // 12–19 位
		var b strings.Builder
		for range n {
			b.WriteByte(byte('0' + rng.IntN(10)))
		}
		digits := b.String()

		if detect.LuhnValid(digits) {
			luhnOnly++
		}
		if detect.BankCardValid(digits) {
			full++
		}
	}

	luhnRate := float64(luhnOnly) / trials * 100
	fullRate := float64(full) / trials * 100
	t.Logf("%d 条随机 12–19 位数字串：", trials)
	t.Logf("  仅 Luhn        误判 %5d 条  %.2f%%", luhnOnly, luhnRate)
	t.Logf("  Luhn+IIN+长度  误判 %5d 条  %.2f%%", full, fullRate)
	t.Logf("  误报下降 %.1f 倍", luhnRate/max(fullRate, 0.0001))

	if fullRate >= luhnRate {
		t.Errorf("加上 IIN 后误报率没有下降：%.2f%% vs %.2f%%", fullRate, luhnRate)
	}

	// 端到端：把这些串放进句子里，看检测器实际报多少
	reported := 0
	for range 2000 {
		n := 12 + rng.IntN(8)
		var b strings.Builder
		for range n {
			b.WriteByte(byte('0' + rng.IntN(10)))
		}
		text := "订单流水 " + b.String() + " 已入库。"
		ents, err := d.Detect(text)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if e.Type == detect.TypeBankCard {
				reported++
			}
		}
	}
	t.Logf("端到端：2000 条随机流水号中被报成卡号的有 %d 条（%.2f%%）",
		reported, float64(reported)/2000*100)
}

// 真实卡号必须仍然全部命中 —— 收紧精确率不能以召回率为代价。
// Real card numbers must still all be found: tightening precision must not
// cost recall.
func TestRealCardsStillDetected(t *testing.T) {
	d := rosterDetector(t)

	// 各卡组织的公开测试卡号
	cards := map[string]string{
		"Visa-16":       "4111111111111111",
		"Visa-13":       "4222222222222",
		"Mastercard":    "5555555555554444",
		"Mastercard-2x": "2223003122003222",
		"Amex":          "378282246310005",
		"Discover":      "6011111111111117",
		"JCB":           "3530111333300000",
		"Diners":        "30569309025904",
	}
	missed := 0
	for name, card := range cards {
		if !detect.BankCardValid(card) {
			t.Errorf("%s %s 未通过校验（网络=%q）", name, card, detect.CardNetwork(card))
			missed++
			continue
		}
		ents, _ := d.Detect("请核对卡号 " + card + " 后扣款。")
		hit := false
		for _, e := range ents {
			if e.Type == detect.TypeBankCard && e.Value == card {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s %s 未被检出：%v", name, card, ents)
			missed++
		}
	}
	t.Logf("%d 个卡组织的公开测试卡号，漏检 %d 个", len(cards), missed)
}

// 版本号不再被报成 IP，而带上下文的地址仍然被检出。
// Version strings are no longer reported as IPs, while addresses with context
// still are.
func TestIPContextTradeoff(t *testing.T) {
	d := rosterDetector(t)

	shouldMiss := []string{
		"kernel 5.15.0.91 driver 535.129.03",
		"schema 3.2.1.0 迁移完成",
		"firmware 1.2.3.4 已刷入",
		"色深 10.10.10.2 采样",
		"protobuf 3.21.12.1 编译通过",
	}
	shouldFind := []string{
		"服务器 192.168.31.240 无响应",
		"网关地址 10.0.0.1 已变更",
		"upstream server 172.16.8.9 timed out",
		"内网 10.10.10.2 不可达",
	}

	fp := 0
	for _, s := range shouldMiss {
		ents, _ := d.Detect(s)
		for _, e := range ents {
			if e.Type == detect.TypeIP {
				fp++
				t.Errorf("版本号被报成 IP：%q -> %q", s, e.Value)
			}
		}
	}
	fn := 0
	for _, s := range shouldFind {
		ents, _ := d.Detect(s)
		found := false
		for _, e := range ents {
			if e.Type == detect.TypeIP {
				found = true
			}
		}
		if !found {
			fn++
			t.Errorf("带上下文的地址被漏掉：%q", s)
		}
	}
	t.Logf("版本号 %d 条误报 %d；带上下文地址 %d 条漏检 %d",
		len(shouldMiss), fp, len(shouldFind), fn)

	// 代价必须被写下来：裸日志行没有周边文字，会被漏掉。
	// The cost, stated: a bare log line has no surrounding words.
	bare := "10.0.0.5 - - [31/Jan/2024:00:00:00] \"GET / HTTP/1.1\" 200"
	ents, _ := d.Detect(bare)
	hasIP := false
	for _, e := range ents {
		if e.Type == detect.TypeIP {
			hasIP = true
		}
	}
	t.Logf("裸日志行 %q 检出 IP = %v —— 这是刻意买下的漏报", bare, hasIP)
}

// 随机构造的「像 PII」的串，整体误报率。
// Overall false-positive rate on generated PII-shaped noise.
func TestOverallFalsePositiveRate(t *testing.T) {
	d := rosterDetector(t)
	rng := rand.New(rand.NewPCG(7, 3))

	templates := []func() string{
		func() string { return fmt.Sprintf("订单 %d 已发货", 10000000000000+rng.Int64N(8999999999999)) },
		func() string { return fmt.Sprintf("时间戳 %d 记录", 1700000000000+rng.Int64N(99999999)) },
		func() string {
			return fmt.Sprintf("版本 %d.%d.%d.%d 发布", rng.IntN(20), rng.IntN(60), rng.IntN(99), rng.IntN(200))
		},
		func() string {
			return fmt.Sprintf("commit %08x%08x%08x%08x", rng.Uint32(), rng.Uint32(), rng.Uint32(), rng.Uint32())
		},
		func() string { return fmt.Sprintf("端口 %d 进程 %d", 1024+rng.IntN(64000), rng.IntN(99999)) },
		func() string {
			return fmt.Sprintf("金额 %d.%02d 元，税率 %d%%", rng.IntN(999999), rng.IntN(100), rng.IntN(20))
		},
	}

	const trials = 12000
	hits := map[detect.EntityType]int{}
	for range trials {
		text := templates[rng.IntN(len(templates))]()
		ents, err := d.Detect(text)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			hits[e.Type]++
		}
	}

	total := 0
	for typ, n := range hits {
		t.Logf("  误报 %s：%d 次", typ, n)
		total += n
	}
	rate := float64(total) / trials * 100
	t.Logf("%d 条「像 PII」的业务文本，误报 %d 次，误报率 %.3f%%", trials, total, rate)
	if rate > 2.0 {
		t.Errorf("误报率 %.3f%% 超过 2%%，精确率达不到 98%% 的目标", rate)
	}
}
