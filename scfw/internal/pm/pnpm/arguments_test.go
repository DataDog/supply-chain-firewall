// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"maps"
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
