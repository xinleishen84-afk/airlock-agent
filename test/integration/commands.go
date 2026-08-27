package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// # 可构建目标由文件系统推导，不写在字符串里
// # Buildable targets are derived from the filesystem, not written in strings
//
// 这个文件针对一个已经发生过的故障：验收测试构建的是 "./cmd/gateway"，  // dangling-ok: 记录已修复的历史故障
// 而包在改名后叫 "./cmd/airlock-gateway"。它自改名起就一直编译失败，
// 而没人发现——因为仓库从未 push，CI 从未跑过。
//
// This targets a failure that happened: an acceptance test built
// "./cmd/gateway" while  // dangling-ok: historical the package had been renamed to
// "./cmd/airlock-gateway". It had been failing to compile ever since, unnoticed
// because the repository was never pushed and CI never ran.
//
// # 为什么不是「上 Bazel」
// # Why not "adopt Bazel"
//
// Bazel 的构建图确实能杜绝悬空引用，但它挡不住这一例：
// exec.Command 里的那个路径在 Bazel 里同样是
// 一个字符串，不是声明的依赖——除非把二进制声明成 data 依赖、用 runfiles
// 定位。真正起作用的不是构建系统，是那条纪律：**别把路径写下来，让它可推导。**
//
// Bazel's build graph does prevent dangling references, but not this instance:
// the path inside exec.Command is a string there too, not a declared
// dependency — unless the binary is declared as a data dep and located through
// runfiles. What does the work is not the build system but the discipline:
// derive the path, do not write it down.
//
// 而 Bazel 的代价对这个项目是不划算的：所有 Go 开发者都期望 go test ./...
// 能跑，引入第二套构建系统是一道实打实的采纳门槛。
//
// And Bazel's cost here is bad: every Go developer expects go test ./... to
// work, and a second build system is a real adoption barrier.

// Command 是一个可构建的二进制目标。
// A buildable binary target.
type Command struct {
	// Name 是目录名，例如 "airlock-agent"。
	Name string

	// ModuleDir 是它所属模块的目录（相对仓库根）。
	ModuleDir string

	// Pkg 是构建时用的包路径，例如 "./cmd/airlock-agent"。
	//
	// 它由 Name 与 ModuleDir 推导而来，不是写死的字面量——
	// 目录改名之后这个值自动跟着变，而引用一个不存在的名字会立刻失败。
	//
	// Derived from Name and ModuleDir rather than written as a literal: a
	// rename changes it automatically, and referencing a name that no longer
	// exists fails immediately.
	Pkg string
}

// repoRoot 返回仓库根目录。
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// Commands enumerates every buildable command in the repository.
// 枚举仓库中每一个可构建的命令。
//
// 从文件系统枚举，而不是维护一张清单。清单会和现实漂移，而这正是
// 本文件要防的那件事。
//
// Enumerated from the filesystem rather than maintained as a list: a list
// drifts from reality, which is the very thing this file exists to prevent.
func Commands(t *testing.T) map[string]Command {
	t.Helper()
	root := repoRoot(t)

	out := map[string]Command{}
	// 主模块的 cmd/，以及各子模块的 cmd/
	moduleDirs := []string{"."}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Name(), "go.mod")); err == nil {
			moduleDirs = append(moduleDirs, e.Name())
		}
	}

	for _, mod := range moduleDirs {
		cmdDir := filepath.Join(root, mod, "cmd")
		cmds, err := os.ReadDir(cmdDir)
		if err != nil {
			continue // 该模块没有 cmd/
		}
		for _, c := range cmds {
			if !c.IsDir() {
				continue
			}
			if _, dup := out[c.Name()]; dup {
				t.Fatalf("命令名 %q 在多个模块下重复——按名字引用会有歧义", c.Name())
			}
			out[c.Name()] = Command{
				Name:      c.Name(),
				ModuleDir: mod,
				Pkg:       "./cmd/" + c.Name(),
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("仓库里没有找到任何可构建命令——枚举逻辑坏了")
	}
	return out
}

// CommandNamed returns one command, failing with the available set if absent.
// 按名字取出一个命令；不存在时报错并列出所有可用的。
//
// 「不存在」必须是一次响亮的失败，而不是一次静默的构建失败。
// 前者告诉你「你要的叫什么、现在有什么」，后者只说 exit status 1。
//
// Absence must fail loudly with the available set, not as a silent build
// failure that says only "exit status 1".
func CommandNamed(t *testing.T, name string) Command {
	t.Helper()
	all := Commands(t)
	c, ok := all[name]
	if !ok {
		names := make([]string, 0, len(all))
		for n := range all {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Fatalf("没有名为 %q 的命令。仓库里现有：%v\n"+
			"多半是目录改名了而这处引用没跟上——"+
			"这正是 %q 这类写死路径会烂掉的方式", name, names, name)
	}
	return c
}

// Build compiles the command and returns the binary path.
// 构建该命令并返回二进制路径。
func (c Command) Build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), c.Name)
	cmd := exec.Command("go", "build", "-o", bin, c.Pkg)
	cmd.Dir = filepath.Join(repoRoot(t), c.ModuleDir)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("构建 %s（模块 %s）失败：%v\n%s", c.Pkg, c.ModuleDir, err, out)
	}
	return bin
}

// buildModule compiles every package in a module.
// 编译一个模块下的全部包。
//
// 主模块的 go build ./... 走不进子模块目录，因此子模块可以坏很久而主模块
// 一直是绿的——otelprocessor 与 nerclient 都是独立模块。
//
// go build ./... in the main module does not descend into submodules, so one
// can stay broken while the main module is green.
func buildModule(t *testing.T, moduleDir string) {
	t.Helper()
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = filepath.Join(repoRoot(t), moduleDir)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("模块 %s 编译失败：%v\n%s", moduleDir, err, out)
	}
}

// moduleDirs lists every Go module directory in the repository.
// 列出仓库中每一个 Go 模块目录。
func moduleDirs(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	dirs := []string{"."}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.Name() != "go.mod" {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil || rel == "." {
			return nil
		}
		dirs = append(dirs, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(dirs)
	return dirs
}

var _ = strings.TrimSpace
var _ = fmt.Sprintf
