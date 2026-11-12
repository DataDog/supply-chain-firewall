// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

func TestProxyCommandSupported10And11(t *testing.T) {
	proxied := []string{
		"install", "i", "add x", "update", "up", "upgrade", "remove x", "rm x", "uninstall x", "un x", "uni x",
		"link ../x", "ln ../x", "unlink", "dislink", "import", "fetch", "dedupe", "rebuild", "rb", "prune",
		"install-test", "it", "patch x", "patch-commit d", "patch-remove x", "deploy out",
		"dlx cowsay", "create vite", "store add x", "self-update", "env use 22", "approve-builds",
		"-C sub add x", "--dir=sub add x", "-r install", "--filter a add x", "-F a add x", "-w add x",
		"--C sub add x", "-rw install", "--workspace-concurrency=2 install", "--network-concurrency 2 install",
		"--reg https://r.test/ install", "recursive install", "dlx cowsay --help", "create vite --version",
		"add x --color always",
	}
	direct := []string{
		"", "run build", "exec tsc", "test", "start", "build", "outdated", "audit", "licenses", "list", "ls",
		"why x", "view x", "info x", "search x", "store path", "config get x", "init", "setup", "root", "bin",
		"pack", "publish", "--help", "-h", "add x --help", "--he add x", "--version", "-v", "add x -v",
		// The option is not value-taking in pnpm's command parse, so 2 is the command.
		"--workspace-concurrency 2 install",
	}
	isolatePnpmEnvironment(t)
	for _, version := range []string{"10.34.9", "11.28.9"} {
		manager := fakePnpm(t, version)
		for _, command := range proxied {
			if !manager.ProxyCommandSupported(strings.Fields(command)) {
				t.Errorf("pnpm %s: %q must be proxied", version, command)
			}
		}
		for _, command := range direct {
			if manager.ProxyCommandSupported(strings.Fields(command)) {
				t.Errorf("pnpm %s: %q must run directly", version, command)
			}
		}
		if !fakePnpmNamed(t, "pnpx", version).ProxyCommandSupported([]string{"cowsay", "--help"}) {
			t.Errorf("pnpm %s: pnpx cowsay --help must be proxied", version)
		}
	}
	manager := fakePnpm(t, "11.28.9")
	for _, command := range []string{"ci", "clean-install", "ic", "install-clean", "with 12.18.0 add x", "with current add x", "runtime set node 22", "rt set node 22"} {
		if !manager.ProxyCommandSupported(strings.Fields(command)) {
			t.Errorf("pnpm 11: %q must be proxied", command)
		}
	}
	if manager.ProxyCommandSupported(strings.Fields("with current run build")) {
		t.Error("pnpm 11: with current classifies the inner command")
	}
}

func TestProxyCommandSupportedUsesEffectiveVersion(t *testing.T) {
	isolatePnpmEnvironment(t)
	manager := fakePnpm(t, "11.28.9")
	if !manager.ProxyCommandSupported([]string{"add", "x"}) || manager.ProxyCommandSupported([]string{"run", "build"}) {
		t.Fatal("add must be proxied and run must not")
	}
	if !fakePnpm(t, "9.15.9").ProxyCommandSupported([]string{"run", "build"}) {
		t.Fatal("an unsupported version is proxied so that the proxy path reports it")
	}
}

func TestParseCommandNetworkOptions10And11(t *testing.T) {
	for _, major := range []int{10, 11} {
		command := strings.Fields("add x --https-pro=http://e:1 --config.noproxy=reg.test --registry https://r.test/ --//r.test/:cafile=/c.pem -- --proxy p")
		parsed := parseCommand(major, false, command)
		want := nodeproxy.Config{
			"https-proxy": {"http://e:1"}, "noproxy": {"reg.test"}, "registry": {"https://r.test/"}, "//r.test/:cafile": {"/c.pem"},
		}
		if !maps.EqualFunc(parsed.network, want, slices.Equal) {
			t.Errorf("pnpm %d: network = %v, want %v", major, parsed.network, want)
		}
		// Registries are discovered but stay with pnpm, which must still use them.
		if wantArgs := []string{"add", "x", "--registry", "https://r.test/", "--", "--proxy", "p"}; !slices.Equal(parsed.args, wantArgs) {
			t.Errorf("pnpm %d: args = %q, want %q", major, parsed.args, wantArgs)
		}
		// Arguments after the dlx package belong to the executed binary.
		dlx := parseCommand(major, false, []string{"dlx", "cowsay", "--proxy=http://x:1"})
		if len(dlx.network) != 0 || !slices.Equal(dlx.args, []string{"dlx", "cowsay", "--proxy=http://x:1"}) {
			t.Errorf("pnpm %d: dlx parsed %+v", major, dlx)
		}
		// --no-proxy disables the proxy in pnpm 10 and 11.
		disabled := parseCommand(major, false, []string{"--no-proxy", "add", "x"})
		if !slices.Equal(disabled.network["proxy"], []string{"false"}) || !slices.Equal(disabled.args, []string{"add", "x"}) {
			t.Errorf("pnpm %d: --no-proxy parsed %+v", major, disabled)
		}
		located := parseCommand(major, false, strings.Fields("--prefix p -C sub -g add x"))
		if located.dir != "sub" || !located.global {
			t.Errorf("pnpm %d: dir=%q global=%v", major, located.dir, located.global)
		}
	}
}

func TestProxyCommandSupported12(t *testing.T) {
	proxied := []string{
		"install", "i", "add x", "update", "up", "remove x", "rm x", "link ../x", "unlink", "dislink", "import", "fetch",
		"dedupe", "rebuild", "rb", "prune", "install-test", "it", "patch x", "patch-commit d", "patch-remove x",
		"deploy out", "dlx cowsay", "create vite", "store add x", "self-update", "env use 22", "approve-builds",
		"pipeline", "-Csub add x", "-rC sub install", "-C=sub add x", "-C sub add x", "--filter a add x", "-w add x",
		"ci", "with 11.28.9 add x", "with current add x", "--workspace-concurrency 2 install", "--store-dir /s install",
		"--lockfile-dir d install", "--frozen-lockfile true install", "--config.registry=http://r/ install",
		"--node-linker hoisted install", "dlx cowsay --help", "create vite --help", "pm install",
	}
	direct := []string{
		"", "-- install", "run build", "exec tsc", "test", "start", "build", "outdated", "view x", "store path",
		"config get x", "add x --help", "--help add", "-h", "--version", "-v", "add x -v",
		// --config.* and --color take a value only with "=", so these run a script.
		"--config.registry http://r/ install", "--color never install",
	}
	isolatePnpmEnvironment(t)
	manager := fakePnpm(t, "12.18.0")
	for _, command := range proxied {
		if !manager.ProxyCommandSupported(strings.Fields(command)) {
			t.Errorf("pnpm 12: %q must be proxied", command)
		}
	}
	for _, command := range direct {
		if manager.ProxyCommandSupported(strings.Fields(command)) {
			t.Errorf("pnpm 12: %q must run directly", command)
		}
	}
	if !fakePnpmNamed(t, "pnpx", "12.18.0").ProxyCommandSupported([]string{"cowsay", "--version"}) {
		t.Error("pnpm 12: pnpx cowsay --version must be proxied")
	}
}

func TestParseCommandNetworkOptions12(t *testing.T) {
	parsed := parseCommand(12, false, strings.Fields("--no-proxy=reg.test add x --https-proxy http://e:1 --registry https://r.test/ --strict-ssl false"))
	want := nodeproxy.Config{"no-proxy": {"reg.test"}, "https-proxy": {"http://e:1"}, "registry": {"https://r.test/"}, "strict-ssl": {"false"}}
	if !maps.EqualFunc(parsed.network, want, slices.Equal) {
		t.Errorf("network = %v, want %v", parsed.network, want)
	}
	if wantArgs := []string{"add", "x", "--registry", "https://r.test/"}; !slices.Equal(parsed.args, wantArgs) {
		t.Errorf("args = %q, want %q", parsed.args, wantArgs)
	}
	for command, dir := range map[string]string{"-Csub add x": "sub", "-C=sub add x": "sub", "-rC sub install": "sub", "--prefix p add x": "p"} {
		if got := parseCommand(12, false, strings.Fields(command)).dir; got != dir {
			t.Errorf("%q: dir = %q, want %q", command, got, dir)
		}
	}
}

// The pinned version parses the command: pnpm 11 rejects -Csub, pnpm 12 reads
// it as the project directory, whose own pin then decides.
func TestMajorUsesPinnedParser(t *testing.T) {
	root := isolatePnpmEnvironment(t)
	project := filepath.Join(root, "parent", "project")
	writePnpmFixture(t, filepath.Join(project, "package.json"), "manifest/pnpm-12-hash.json")
	writePnpmFixture(t, filepath.Join(project, "sub", "package.json"), "manifest/pnpm-10.json")
	manager := fakePnpm(t, "11.28.9")
	command := []string{"-Csub", "add", "x"}
	if !manager.ProxyCommandSupported(command) {
		t.Fatal("-Csub add x must be proxied")
	}
	if major, err := manager.major(command); err != nil || major != 10 {
		t.Fatalf("major = %d (error %v), want 10 from sub's pin", major, err)
	}
	if major, err := manager.major([]string{"add", "x"}); err != nil || major != 12 {
		t.Fatalf("major = %d (error %v), want 12 from the project pin", major, err)
	}
}
