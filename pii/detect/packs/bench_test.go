package packs

import "testing"

// 一段掺杂 PII 的真实提示词。
// A realistic prompt with PII mixed in.
const benchPrompt = `客户张伟（手机 13812345678，身份证 11010519491231002X）` +
	`在 2024 年 3 月提交了退款申请，涉及卡号 4111 1111 1111 1111，` +
	`发票抬头为统一社会信用代码 91110108MA01ABCD7X 的公司。` +
	`请根据以上信息生成一份退款说明，并把结果发送到 zhang.wei@example.com。`

// 装更多国家包要付多少钱？
// What does loading more country packs cost?
//
// 这是插拔式设计要回答的问题：只服务本国的部署，不该为另外几十个国家的
// 正则付费。这里量出的是加载 1 个包与加载全部包在 hot path 上的差。
// This is the question a pluggable design has to answer: a single-country
// deployment should not pay for forty other countries. Measured here as the
// hot-path difference between one pack and all of them.
func BenchmarkPackScaling(b *testing.B) {
	cases := []struct {
		name  string
		codes []string
	}{
		{"GEN", []string{"GEN"}},
		{"GEN+CN", []string{"GEN", "CN"}},
		{"全部/all", Available()},
	}
	for _, tc := range cases {
		reg, err := NewRegistry(tc.codes)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(benchPrompt)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := reg.Detect(benchPrompt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// 构建一个包要多久——决定进程启动能不能承受把包做成动态配置。
// How long building a pack takes — decides whether packs can be configuration.
func BenchmarkPackBuild(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Load(Available()...); err != nil {
			b.Fatal(err)
		}
	}
}
