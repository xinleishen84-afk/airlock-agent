package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// TestWrapperDelegatesGapReporting 证明包装层不会吞掉覆盖缺口告警。
// Proves the wrapper does not swallow the coverage-gap warning.
//
// # 这条测试对应一次真实事故
// # This test corresponds to a real incident
//
// 覆盖缺口告警说的是「姓名、地址、机构名这几类完全裸奔」。它此前靠
// detector.(*detect.CompositeDetector) 取。证据链包上之后断言失败，
// 告警**静默消失**——不报错、日志里不再出现，看起来和「没有缺口」一模一样。
// sidecar 的 /stats coverage_gaps 与启动告警空了整整一轮，而缺口一直在。
//
// The warning says names, addresses and organizations are fully exposed. It was
// read through a concrete-type assertion that any wrapper breaks. Once the
// evidence chain wrapped the detector the assertion failed and the warning
// vanished — indistinguishable from "no gaps". The sidecar's coverage_gaps and
// startup warning were empty for a full round while the gaps remained.
func TestWrapperDelegatesGapReporting(t *testing.T) {
	inner := detect.NewCompositeDetector(nil, 0)
	want := inner.Missing()
	if len(want) == 0 {
		t.Fatal("空装配本应报告缺口，测试前提不成立")
	}

	v, err := NewDefaultEvidenceValidator()
	if err != nil {
		t.Fatalf("构造证据链: %v", err)
	}
	wrapped := WrapDetector(inner, v)

	g, ok := wrapped.(detect.GapReporter)
	if !ok {
		t.Fatal("包装后的检测器不再实现 detect.GapReporter——" +
			"覆盖缺口告警会从运维界面整条消失")
	}
	if got := g.Missing(); len(got) != len(want) {
		t.Fatalf("包装层未透传缺口：want %v, got %v", want, got)
	}
}

// TestNoConcreteDetectorAssertions 禁止用具体类型取覆盖缺口。
// Forbids reading coverage gaps through a concrete-type assertion.
//
// 具体类型断言的坏处不是它会出错，而是它出错时**没有任何声音**：
// 断言失败走 else 分支，告警不再产生，看起来像通过。任何人往检测器外面
// 包一层（证据链、指标、缓存都会这么做）就会重现这次事故。
// 因此在源码层面禁掉这个写法，而不是靠记得。
//
// A concrete-type assertion is dangerous not because it can be wrong but
// because being wrong is silent: the else branch produces no warning, which
// reads as a pass. Any future wrapper — metrics, caching, the evidence chain —
// reproduces the incident. Ban the shape in source rather than rely on memory.
func TestNoConcreteDetectorAssertions(t *testing.T) {
	root := repoRoot(t)
	const bad = ".(*detect.CompositeDetector)"
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, bad) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s:%d 用具体类型断言取检测器——请改用 detect.GapReporter，"+
					"否则任何包装层都会让覆盖缺口告警静默消失：\n\t%s",
					rel, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历源码: %v", err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("取工作目录: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("未找到仓库根")
	return ""
}
