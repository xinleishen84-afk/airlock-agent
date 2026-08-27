package integration

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// # 悬空引用扫描
// # Dangling-reference scan
//
// 这是「别把路径写下来」那条纪律的兜底：推导优先，但总有地方绕不开写死
// ——CI 的 YAML、Dockerfile 的 ENTRYPOINT、K8s 的 args、README 的示例命令。
// 这些文件不经过 Go 编译器，改名之后不会有任何东西告诉你它们烂了。
//
// The backstop for "derive, do not write down": some places cannot avoid a
// literal — CI YAML, a Dockerfile ENTRYPOINT, K8s args, a README example.
// None of these pass through the Go compiler, and after a rename nothing says
// they are stale.
//
// 这一组用例把它们全部扫一遍，逐条解析。它给出的是 Bazel 构建图的那条
// 性质——「不存在未被索引的悬空引用」——而代价是一个 go test，
// 不是第二套构建系统。
//
// These tests scan them all. The property is Bazel's — no unindexed dangling
// reference — at the cost of one go test rather than a second build system.

// pkgPathPattern 匹配包路径引用。
var pkgPathPattern = regexp.MustCompile(`\./cmd/[a-zA-Z0-9_-]+`)

// allowMarker 是一处**声明过的**历史引用。
//
// 扫描器不区分「代码里的引用」与「注释里讲历史」——它也不该区分：
// 一段描述已不存在路径的注释，同样是会误导下一个人的悬空引用。
//
// 但历史确实要记下来。所以豁免必须是显式声明的，而且要带理由：
// 写下 dangling-ok 的人知道自己在做什么，而没写的人会被拦下。
// 这正是声明式依赖图的那条性质——豁免存在，但它必须被声明。
//
// The scanner does not distinguish a reference in code from prose in a
// comment, and should not: a comment describing a path that no longer exists
// misleads the next reader just as much. But history is worth recording, so an
// exemption must be declared with a reason. Whoever writes dangling-ok knows
// what they are doing; whoever does not is stopped.
const allowMarker = "dangling-ok:"

// scanTargets 是要扫描的文件类型与它们各自的豁免。
type scanTarget struct {
	label   string
	exts    []string
	skipDir []string
}

var targets = []scanTarget{
	{label: "Go 源码", exts: []string{".go"}, skipDir: []string{"genproto", ".git"}},
	{label: "CI 与部署清单", exts: []string{".yml", ".yaml"}, skipDir: []string{".git"}},
	{label: "容器与脚本", exts: []string{".sh", ""}, skipDir: []string{".git", ".venv"}},
	{label: "文档", exts: []string{".md"}, skipDir: []string{".git"}},
}

// 仓库里每一处写死的包路径都必须解析得到一个真实存在的包。
// Every hardcoded package path in the repository must resolve.
//
// 实测抓到过一次：验收测试构建的包名在改名后已不存在，  // dangling-ok: 历史
// 它自改名起就一直编译失败。
func TestNoDanglingPackageReferences(t *testing.T) {
	root := repoRoot(t)
	known := Commands(t)

	type hit struct {
		file string
		line int
		ref  string
	}
	var dangling []hit
	scanned := 0

	for _, target := range targets {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				for _, skip := range target.skipDir {
					if d.Name() == skip {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if !matchesExt(d.Name(), target.exts) {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil // 读不了的跳过，不是本用例要管的
			}
			scanned++

			rel, _ := filepath.Rel(root, path)
			for i, line := range strings.Split(string(content), "\n") {
				if strings.Contains(line, allowMarker) {
					continue // 显式声明过的历史引用
				}
				for _, ref := range pkgPathPattern.FindAllString(line, -1) {
					name := strings.TrimPrefix(ref, "./cmd/")
					if _, ok := known[name]; !ok {
						dangling = append(dangling, hit{rel, i + 1, ref})
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	names := make([]string, 0, len(known))
	for n := range known {
		names = append(names, n)
	}
	sort.Strings(names)
	t.Logf("扫描 %d 个文件，仓库现有命令：%v", scanned, names)

	for _, d := range dangling {
		t.Errorf("%s:%d 引用了不存在的命令 %q\n"+
			"  现有：%v\n"+
			"  这类引用不经过 Go 编译器，改名之后没有任何东西会告诉你它烂了。\n"+
			"  若这是一处有意保留的历史引用，在该行加上 %q 并说明理由",
			d.file, d.line, d.ref, names, allowMarker)
	}
}

// 每一个 cmd/ 下的命令都必须至少被一处引用。
// Every command under cmd/ must be referenced somewhere.
//
// 反方向的悬空：一个没有任何东西构建、测试或部署的二进制，
// 会安静地烂掉——它编译不过也没人知道，因为没人编译它。
//
// The other direction: a binary that nothing builds, tests or deploys rots
// silently, because nothing compiles it.
func TestEveryCommandIsReferenced(t *testing.T) {
	root := repoRoot(t)
	known := Commands(t)
	referenced := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "genproto" {
				return filepath.SkipDir
			}
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for name := range known {
			// 命令自己的源文件不算引用
			if strings.Contains(path, filepath.Join("cmd", name)) {
				continue
			}
			if strings.Contains(string(content), name) {
				referenced[name] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for name := range known {
		if !referenced[name] {
			t.Errorf("命令 %q 没有被任何文件引用——没有 CI 构建它、没有测试跑它、"+
				"没有部署清单提到它。它会安静地烂掉", name)
		}
	}
	t.Logf("%d 个命令全部有引用", len(known))
}

// 每一个模块都必须能构建，且每一个命令都必须能构建。
// Every module and every command must build.
//
// 主模块的 go build ./... 走不进子模块目录，因此子模块可以坏很久而主模块
// 一直是绿的。这条把它们全部跑一遍。
//
// go build ./... in the main module does not descend into submodules, so a
// submodule can stay broken while the main module is green.
func TestEveryModuleAndCommandBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("构建全部模块较慢")
	}

	for _, mod := range moduleDirs(t) {
		t.Run("模块 "+mod, func(t *testing.T) {
			buildModule(t, mod)
		})
	}

	for name, c := range Commands(t) {
		t.Run("命令 "+name, func(t *testing.T) {
			_ = c.Build(t)
		})
	}
}

func matchesExt(name string, exts []string) bool {
	ext := filepath.Ext(name)
	for _, e := range exts {
		if e == "" {
			// 无扩展名：只认 Dockerfile 这类
			if ext == "" && strings.Contains(strings.ToLower(name), "dockerfile") {
				return true
			}
			continue
		}
		if ext == e {
			return true
		}
	}
	return false
}
