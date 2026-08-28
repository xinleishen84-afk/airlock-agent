package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// # 部署清单与二进制的对齐，只有真跑才能验
// # Manifest-to-binary alignment can only be verified by running
//
// 这个文件针对一个已经发生过的故障：会话一致性被做成必选声明时，校验只
// 写进了 cmd/airlock-agent 的 main，而 --session-consistency 同时被写进了
// 三份部署清单。Advanced 二进制持有同一种会话保险库、有同样的暴露面，
// 却没有这个 flag——deploy/advanced-sidecar.yaml 会让它以
// "flag provided but not defined" 崩溃循环，出货清单直接起不来。
//
// 全部单元测试和集成测试都是绿的。清单是 YAML，flag 定义在 Go 里，
// 两者之间没有任何一条编译期或测试期的连线，所以这类漂移只能靠真跑发现。
//
// This targets a failure that happened: when session consistency became a
// required declaration, the check went into cmd/airlock-agent's main only while
// --session-consistency was added to three deployment manifests. The Advanced
// binary holds the same vault and the same exposure but never defined the flag,
// so deploy/advanced-sidecar.yaml made it crash-loop on "flag provided but not
// defined" — the shipped manifest could not start.
//
// Every test was green. The manifest is YAML, the flag lives in Go, and nothing
// connects them at compile time or test time.

// manifestArg 是清单里传给某个二进制的一个参数。
type manifestArg struct {
	file string // 清单文件名
	flag string // 形如 "--session-consistency"
	line int
}

// argRe 匹配清单 args 列表里的一项：`- --flag=value` 或 `- --flag`
var argRe = regexp.MustCompile(`^\s*-\s+(--[a-z0-9-]+)`)

// imageRe 从 image 行取出镜像名末段，用来推断该容器跑的是哪个二进制。
var imageRe = regexp.MustCompile(`image:\s*\S*/([a-z0-9-]+):`)

// TestManifestFlagsExistInBinaries 保证部署清单传的每个 flag，目标二进制都定义了。
// Every flag a manifest passes must be defined by the binary it runs.
//
// 用 --help 的输出比对，而不是解析 Go 源码里的 flag.String 调用：--help
// 打印的是这个二进制**实际注册**的 flag 集合，源码解析会被条件注册、
// 跨包注册和别名骗过去。要验的是运行时行为，就问运行时。
//
// Compared against --help output rather than parsed from flag.String calls in
// source: --help prints what the binary actually registered, while source
// parsing is fooled by conditional registration, cross-package registration and
// aliases. The question is about runtime behaviour, so ask the runtime.
func TestManifestFlagsExistInBinaries(t *testing.T) {
	root := repoRoot(t)
	byBinary := manifestArgsByBinary(t, root)
	if len(byBinary) == 0 {
		t.Fatal("没有从 deploy/ 里解析出任何容器参数——解析逻辑或清单布局变了")
	}

	all := Commands(t)
	for binary, args := range byBinary {
		cmd, ok := all[binary]
		if !ok {
			// 镜像名与 cmd/ 目录名对不上：可能是分析器这类非 Go 组件，
			// 也可能是清单引用了一个不存在的二进制。后者才是问题，
			// 但这里无法区分，交给 TestManifestImagesAreBuildable 判断。
			continue
		}
		t.Run(binary, func(t *testing.T) {
			defined := definedFlags(t, cmd)
			for _, a := range args {
				if !defined[a.flag] {
					t.Errorf("%s:%d 传了 %s，而 %s 没有定义这个 flag——"+
						"Pod 会以 \"flag provided but not defined\" 崩溃循环。"+
						"该二进制已定义：%s",
						a.file, a.line, a.flag, cmd.Pkg, strings.Join(sortedKeys(defined), " "))
				}
			}
		})
	}
}

// TestManifestImagesAreBuildable 保证清单引用的每个镜像都有东西能构建它。
// Every image a manifest references must have something in-tree that builds it.
//
// 针对的故障：deploy/advanced-*.yaml 引用 airlock-analyzer 镜像，而构建它
// 的 Python 代码与 Dockerfile 都在仓库外，那个目录还不是 git 仓库。克隆
// 下来的仓库无法构建出一个自己清单里就在引用的镜像，而这件事没有任何
// 检查会发现——清单是一份对外部世界的断言，没人核对过它。
//
// The failure this targets: deploy/advanced-*.yaml referenced the
// airlock-analyzer image while the Python code and Dockerfile that build it
// lived outside the repository, in a directory that was not even a git repo. A
// clone could not build an image its own manifests referenced, and nothing
// checked — a manifest is an assertion about the outside world that no one
// verified.
func TestManifestImagesAreBuildable(t *testing.T) {
	root := repoRoot(t)
	all := Commands(t)

	for _, file := range manifestFiles(t, root) {
		b, err := os.ReadFile(filepath.Join(root, "deploy", file))
		if err != nil {
			t.Fatalf("读取 %s: %v", file, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			m := imageRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			name := m[1]
			if _, ok := all[name]; ok {
				continue // 是本仓库的 Go 二进制
			}
			if hasDockerfileFor(root, name) {
				continue // 有 Dockerfile 能构建它
			}
			t.Errorf("%s:%d 引用镜像 %q，但仓库里既没有同名 cmd/ 目录，"+
				"也没有能构建它的 Dockerfile——克隆下来的仓库装不出这个部署",
				file, i+1, name)
		}
	}
}

// hasDockerfileFor 判断仓库里是否有能构建该镜像的 Dockerfile。
//
// 约定：镜像 airlock-analyzer 由 analyzer/Dockerfile 构建。只认这条约定，
// 不做模糊匹配——模糊匹配会让「找到了一个碰巧同名的文件」被当成通过。
func hasDockerfileFor(root, image string) bool {
	// airlock-analyzer -> analyzer
	short := strings.TrimPrefix(image, "airlock-")
	for _, p := range []string{
		filepath.Join(root, short, "Dockerfile"),
		filepath.Join(root, image, "Dockerfile"),
		filepath.Join(root, "Dockerfile."+short),
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// definedFlags 取出一个二进制实际注册的全部 flag。
func definedFlags(t *testing.T, c Command) map[string]bool {
	t.Helper()
	bin := c.Build(t)

	// --help 走 flag 包的默认行为：打印用法后退出，退出码非 0，这是正常的
	cmd := exec.Command(bin, "--help")
	out, _ := cmd.CombinedOutput()

	defined := map[string]bool{}
	// flag 包的用法输出里每个 flag 以 "  -name" 开头
	re := regexp.MustCompile(`(?m)^\s{1,4}-([a-z0-9-]+)`)
	for _, m := range re.FindAllStringSubmatch(string(out), -1) {
		// 清单里写的是 --flag，flag 包打印的是 -flag，统一成两个横杠比较
		defined["--"+m[1]] = true
	}
	if len(defined) == 0 {
		t.Fatalf("从 %s --help 里没解析出任何 flag，输出：\n%s", c.Pkg, out)
	}
	return defined
}

// manifestArgsByBinary 解析 deploy/ 下全部清单，按二进制归类它们传的 flag。
func manifestArgsByBinary(t *testing.T, root string) map[string][]manifestArg {
	t.Helper()
	out := map[string][]manifestArg{}
	for _, file := range manifestFiles(t, root) {
		b, err := os.ReadFile(filepath.Join(root, "deploy", file))
		if err != nil {
			t.Fatalf("读取 %s: %v", file, err)
		}
		current := ""
		for i, line := range strings.Split(string(b), "\n") {
			if m := imageRe.FindStringSubmatch(line); m != nil {
				current = m[1]
				continue
			}
			if current == "" {
				continue
			}
			if m := argRe.FindStringSubmatch(line); m != nil {
				out[current] = append(out[current],
					manifestArg{file: "deploy/" + file, flag: m[1], line: i + 1})
			}
		}
	}
	return out
}

// manifestFiles 列出 deploy/ 下的清单。
func manifestFiles(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "deploy"))
	if err != nil {
		t.Fatalf("读取 deploy/: %v", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
