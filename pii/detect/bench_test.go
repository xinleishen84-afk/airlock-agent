package detect

import (
	"fmt"
	"strings"
	"testing"
)

// 典型负载：一段中英混合的 Agent 提示词。
// Typical load: a mixed Chinese/English agent prompt.
var benchText = "客户张伟投诉订单 SO-20260826-001，联系电话 13812345678，" +
	"邮箱 zhang.wei@corp.com，身份证 110101199003078515，" +
	"付款卡号 4111 1111 1111 1111，收货地址北京市朝阳区建国路88号。" +
	"Please contact the customer and confirm the refund before 2026-09-01."

// benchLongText 模拟携带长系统提示词的真实请求。
// benchLongText simulates a real request carrying a long system prompt.
var benchLongText = strings.Repeat(
	"你是企业客服助手，遵循以下 SOP：核对身份、确认诉求、给出方案、记录工单。", 40) +
	benchText

// BenchmarkRegexLayer measures the hot-path layer alone.
// 单独度量 hot-path 那一层。
//
// This is the number the "microsecond-level" claim rests on. Every SSE request
// pays it, so it must be measured rather than asserted.
// 「微秒级」这个断言就落在这个数字上。每个 SSE 请求都要付它，
// 因此必须实测而非断言。
func BenchmarkRegexLayer(b *testing.B) {
	d := NewRegexDetector()
	b.ReportAllocs()
	b.SetBytes(int64(len(benchText)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := d.Detect(benchText); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRegistryLocal measures the full local pipeline: predefined
// recognizers with checksums and context boosting, no network.
// 度量完整的本地管道：预定义识别器 + 校验和 + 上下文加权，无网络。
func BenchmarkRegistryLocal(b *testing.B) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(benchText)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := reg.Detect(benchText); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRegistryLongPrompt measures the same path on a realistic prompt with
// a long cached system prefix.
// 在带长系统前缀的真实提示词上度量同一路径。
func BenchmarkRegistryLongPrompt(b *testing.B) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(benchLongText)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := reg.Detect(benchLongText); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkChecksumOnly isolates the validator cost.
// 单独隔离校验位的开销。
func BenchmarkChecksumOnly(b *testing.B) {
	cases := []struct {
		name string
		fn   func(string) bool
		in   string
	}{
		{"Luhn", LuhnValid, "4111111111111111"},
		{"CNIDCard", CNIDCardValid, "110101199003078515"},
		{"CNUSCC", CNUSCCValid, "91110108MA01ABCD7X"},
		{"IBAN", IBANValid, "GB82WEST12345698765432"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.fn(c.in)
			}
		})
	}
}

// BenchmarkGazetteer measures roster matching at enterprise scale.
// 在企业规模下度量名册匹配。
//
// A real deployment loads thousands of employee and customer names. If the
// gazetteer degrades linearly with roster size it cannot stay on the hot path.
// 真实部署会载入数千条员工与客户姓名。若名册开销随规模线性退化，
// 它就无法留在 hot-path 上。
func BenchmarkGazetteer(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		terms := make([]string, n)
		for i := range terms {
			terms[i] = fmt.Sprintf("员工%04d", i)
		}
		terms[n/2] = "张伟"
		gaz, err := NewGazetteerDetector(map[EntityType][]string{TypeName: terms}, false, 2)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("terms=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				gaz.Detect(benchText)
			}
		})
	}
}
