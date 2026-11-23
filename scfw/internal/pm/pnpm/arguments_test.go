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
		// Every built-in that does not fetch a package is proxied too.
		"outdated", "audit", "licenses", "list", "ls", "why x", "init", "setup", "root", "bin", "pack",
		"publish", "store path", "config get x", "doctor",
	}
	direct := []string{
		"", "run build", "exec tsc", "test", "start", "build", "--help", "-h", "add x --help", "--he add x",
		"--version", "-v", "add x -v",
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
	// The commands pnpm 10 hands to npm only as the raw first argument are
	// proxied there; after an option pnpm does not know them, so they run (and
	// fail) as scripts. pnpm 11 implements them itself and proxies them either
	// way.
	for version, view := range map[string]map[string]bool{
		"10.34.9": {"view x": true, "search x": true, "info x": true, "-C sub view x": false},
		"11.28.9": {"view x": true, "search x": true, "info x": true, "-C sub view x": true},
	} {
		manager := fakePnpm(t, version)
		for command, proxiedCommand := range view {
			if got := manager.ProxyCommandSupported(strings.Fields(command)); got != proxiedCommand {
				t.Errorf("pnpm %s: %q proxied = %v, want %v", version, command, got, proxiedCommand)
			}
		}
	}
	manager := fakePnpm(t, "11.28.9")
	for _, command := range []string{
		"ci", "clean-install", "ic", "install-clean", "with 12.18.0 add x", "with current add x",
		"runtime set node 22", "rt set node 22", "clean", "purge", "pack-app main.js", "setup",
	} {
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
		// Every built-in that does not fetch a package is proxied too.
		"outdated", "view x", "store path", "config get x", "clean", "purge", "setup", "tasks",
		"pack-app main.js", "fund", "catalog migrate", "shim", "permissions", "approve", "pm tasks",
	}
	direct := []string{
		"", "-- install", "run build", "exec tsc", "test", "t", "tst", "start", "stop", "build", "add x --help",
		"--help add", "-h", "--version", "-v", "add x -v",
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

// expectedProxied and expectedDirect are the written-out proxy selection for
// every pnpm 10, 11, and 12 built-in command and alias, plus the pnpm 10 npm
// pass-through names, in a project that declares none of the scripts that can
// override a built-in: scripts run directly and everything else is proxied.
var expectedProxied = map[int][]string{
	10: {
		// Built-in commands.
		"add", "approve-builds", "audit", "bin", "cache", "cat-file", "cat-index", "ci", "completion",
		"completion-server", "config", "create", "dedupe", "deploy", "dlx", "doctor", "env", "fetch",
		"find-hash", "get", "help", "ignored-builds", "import", "init", "install", "install-test",
		"licenses", "link", "list", "ll", "outdated", "pack", "patch", "patch-commit", "patch-remove",
		"prune", "publish", "rebuild", "remove", "root", "self-update", "server", "set",
		"setup", "store", "unlink", "update", "why",
		// Aliases.
		"c", "clean-install", "dislink", "i", "ic", "install-clean", "it", "la", "ln", "ls",
		"rb", "rm", "un", "uni", "uninstall", "up", "upgrade",
		// npm pass-through commands.
		"access", "adduser", "bugs", "deprecate", "dist-tag", "docs", "edit", "find", "home", "info",
		"issues", "login", "logout", "owner", "ping", "prefix", "profile", "pkg", "repo", "s", "se",
		"search", "set-script", "show", "star", "stars", "team", "token", "unpublish", "unstar", "v",
		"version", "view", "whoami", "xmas",
	},
	11: {
		// Built-in commands.
		"access", "add", "approve-builds", "audit", "bin", "bugs", "cache", "cat-file", "cat-index",
		"change", "ci", "clean", "completion", "completion-server", "config", "create", "dedupe",
		"deploy", "deprecate", "dist-tag", "dlx", "doctor", "docs", "edit", "env", "fetch", "find-hash",
		"get", "help", "ignored-builds", "import", "init", "install", "install-test", "lane",
		"licenses", "link", "list", "ll", "login", "logout", "outdated", "owner", "pack", "pack-app",
		"patch", "patch-commit", "patch-remove", "peers", "ping", "pkg", "prefix", "profile", "prune",
		"publish", "rebuild", "remove", "repo", "root", "runtime", "sbom", "search",
		"self-update", "set", "set-script", "setup", "stage", "star", "stars", "store", "team",
		"token", "undeprecate", "unlink", "unpublish", "unstar", "update", "version", "view",
		"whoami", "why", "with", "xmas",
		// Aliases.
		"adduser", "c", "clean-install", "dislink", "dist-tags", "find", "home", "i", "ic", "info",
		"install-clean", "issues", "it", "la", "ln", "ls", "owners", "purge", "rb",
		"rm", "rt", "s", "se", "show", "ss", "un", "uni", "uninstall", "up", "upgrade", "v",
	},
	12: {
		// Built-in commands.
		"access", "add", "approve", "approve-builds", "audit", "bin", "bugs", "cache", "catalog",
		"cat-file", "cat-index", "change", "ci", "clean", "completion", "completion-server", "config",
		"create", "dedupe", "deploy", "deprecate", "dist-tag", "dlx", "doctor", "docs", "edit", "env",
		"fetch", "find-hash", "fund", "get", "help", "ignored-builds",
		"import", "init", "install", "install-test", "lane", "licenses", "link", "list", "ll", "login",
		"logout", "outdated", "owner", "pack", "pack-app", "patch", "patch-commit", "patch-remove",
		"peers", "permissions", "ping", "pipeline", "pkg", "prefix", "profile", "prune", "publish",
		"purge", "rb", "rebuild", "remove", "repo", "root", "runtime", "sbom", "search",
		"self-update", "set", "set-script", "setup", "shim", "stage", "star", "stars", "store",
		"tasks", "team", "token", "undeprecate", "unlink", "unpublish", "unstar", "update", "version",
		"view", "whoami", "why", "with", "xmas",
		// Aliases.
		"adduser", "c", "clean-install", "dislink", "dist-tags", "find", "home", "i", "ic", "info",
		"install-clean", "issues", "it", "la", "ln", "ls", "owners", "purge", "rb",
		"rm", "rt", "s", "se", "show", "ss", "un", "uni", "uninstall", "up", "upgrade", "v",
		"licences",
	},
}

// expectedDirect are the commands that always run a package script, so pnpm
// and SCFW run them directly: the script commands, and the pnpm 12 script
// shortcuts, and a name that is not a built-in.
// The recursive names select no command on their own, which pnpm reports
// like an empty command line.
var expectedDirect = map[int][]string{
	10: {"run", "run-script", "exec", "restart", "test", "start", "stop", "build", "recursive", "m", "multi"},
	11: {"run", "run-script", "exec", "restart", "test", "start", "stop", "build", "recursive", "m", "multi"},
	12: {"run", "run-script", "exec", "restart", "test", "t", "tst", "start", "stop", "build", "recursive", "m", "multi"},
}

func TestCommandClassification(t *testing.T) {
	isolatePnpmEnvironment(t)
	for major, version := range pnpmVersions {
		manager := fakePnpm(t, version)
		for _, name := range expectedProxied[major] {
			if !manager.ProxyCommandSupported([]string{name}) {
				t.Errorf("pnpm %d: %q must be proxied", major, name)
			}
		}
		for _, name := range expectedDirect[major] {
			if manager.ProxyCommandSupported([]string{name}) {
				t.Errorf("pnpm %d: %q must run directly", major, name)
			}
		}
	}
}

// A new or renamed pnpm command must be added to the explicit expectations
// above, or the classifier silently decides it on its own.
func TestCommandClassificationCoversProductionTables(t *testing.T) {
	for major := range pnpmVersions {
		aliases := nopt11.aliases
		switch major {
		case 10:
			aliases = nopt10.aliases
		case 12:
			aliases = strictAliases
		}
		expected := slices.Concat(expectedProxied[major], expectedDirect[major])
		for _, name := range slices.Concat(builtinCommands[major], slices.Collect(maps.Keys(aliases))) {
			if !slices.Contains(expected, name) {
				t.Errorf("pnpm %d: %q is missing from the expected classifications", major, name)
			}
		}
		if major == 10 {
			for _, name := range npmPassthrough10 {
				if !slices.Contains(expected, name) {
					t.Errorf("pnpm 10: %q is missing from the expected classifications", name)
				}
			}
		}
		for _, name := range expected {
			known := slices.Contains(builtinCommands[major], name) || slices.Contains(npmPassthrough10, name) ||
				func() bool { _, found := aliases[name]; return found }()
			if !known && !slices.Contains(expectedDirect[major], name) {
				t.Errorf("pnpm %d: %q is not a pnpm command", major, name)
			}
		}
	}
}

// A same-named package.json script replaces an overridable built-in, looked up
// under the name as typed. A ' + bt + 'pm' + bt + ' prefix forces the built-in, and
// pnpm 11 keeps it under --global; pnpm 10 has no overrides, so the name is a
// script anyway.
func TestScriptOverrides(t *testing.T) {
	root := isolatePnpmEnvironment(t)
	writePnpmFixture(t, filepath.Join(root, "parent", "project", "package.json"), "manifest/scripts.json")
	for _, test := range []struct {
		version string
		command string
		proxied bool
	}{
		{"10.34.9", "clean", false},
		{"11.28.9", "clean", false},
		{"11.28.9", "purge", false},
		{"11.28.9", "rebuild", false},
		{"11.28.9", "rb", false},
		{"11.28.9", "deploy", false},
		{"11.28.9", "setup", false},
		{"11.28.9", "-g clean", true},
		{"11.28.9", "pm clean", true},
		{"11.28.9", "outdated", true},
		{"12.18.0", "rb", false},
		{"12.18.0", "tasks", false},
		{"12.18.0", "pm rb", true},
		{"12.18.0", "pm tasks", true},
		{"12.18.0", "-g clean", false},
		{"12.18.0", "outdated", true},
	} {
		manager := fakePnpm(t, test.version)
		if got := manager.ProxyCommandSupported(strings.Fields(test.command)); got != test.proxied {
			t.Errorf("pnpm %s: %q proxied = %v, want %v", test.version, test.command, got, test.proxied)
		}
	}
}
