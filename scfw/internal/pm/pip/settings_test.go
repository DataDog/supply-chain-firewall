// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// No interpreter exists in this fixture. Discovering settings must only read
// the launcher/configuration; it cannot import pip or execute embedded scripts.
func goDiscoveryPip(t *testing.T) Pip {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(key, "PIP_") || strings.HasSuffix(strings.ToLower(key), "_proxy") || slices.Contains([]string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "REQUEST_METHOD"}, key) {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	// An unrelated scheme suppresses urllib's native macOS fallback without
	// changing HTTP(S) routing, keeping these tests independent of host settings.
	t.Setenv("scfw_test_proxy", "unused")
	root := t.TempDir()
	prefix := filepath.Join(root, "venv")
	t.Setenv("PIP_CONFIG_FILE", os.DevNull)
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_DIRS", filepath.Join(root, "global"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "user"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	executable := filepath.Join(prefix, "bin", "pip")
	writePipFixture(t, executable, fmt.Sprintf(readPipFixture(t, "config/launcher.tmpl"), filepath.Join(prefix, "bin", "python")))
	writePipFixture(t, filepath.Join(prefix, "pyvenv.cfg"), readPipFixture(t, "config/pyvenv.cfg"))
	return Pip{executable: executable, version: pm.Version{Major: 26, Minor: 2, Patch: 2}}
}

func writePipFixture(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGoDiscoveryConfigurationPrecedence(t *testing.T) {
	globalFixture := readPipFixture(t, "config/global.conf")
	legacyUserFixture := readPipFixture(t, "config/legacy-user.conf")
	userFixture := readPipFixture(t, "config/user.conf")
	siteFixture := readPipFixture(t, "config/site.conf")
	manager := goDiscoveryPip(t)
	t.Setenv("PIP_CONFIG_FILE", "")
	if err := os.Unsetenv("PIP_CONFIG_FILE"); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Dir(filepath.Dir(manager.executable))
	writePipFixture(t, filepath.Join(os.Getenv("XDG_CONFIG_DIRS"), "pip", "pip.conf"), globalFixture)
	writePipFixture(t, filepath.Join(os.Getenv("HOME"), ".pip", "pip.conf"), legacyUserFixture)
	writePipFixture(t, filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "pip", "pip.conf"), userFixture)
	writePipFixture(t, filepath.Join(prefix, "pip.conf"), siteFixture)
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"install", "project"}, "http://site.example"},
		{[]string{"--timeout", "1", "download", "project"}, "http://site.example"},
		{[]string{"--isolated", "install", "project"}, "http://site.example"},
	} {
		got, err := manager.settings(test.args)
		if err != nil {
			t.Fatal(err)
		}
		if got.HTTPS != test.want || got.Cert != "/global.pem" {
			t.Fatalf("%v: proxy=%q cert=%q", test.args, got.HTTPS, got.Cert)
		}
	}
	t.Setenv("PIP_PROXY", "http://environment.example")
	got, err := manager.settings([]string{"download", "project"})
	if err != nil || got.HTTPS != "http://environment.example" {
		t.Fatalf("environment precedence: %+v %v", got, err)
	}
	got, err = manager.settings([]string{"--proxy=http://command.example", "download", "project"})
	if err != nil || got.HTTPS != "http://command.example" {
		t.Fatalf("command precedence: %+v %v", got, err)
	}
	t.Setenv("PIP_CONFIG_FILE", os.DevNull)
	t.Setenv("PIP_PROXY", "")
	got, err = manager.settings([]string{"install", "project"})
	if err != nil || got.Cert != "" || got.HTTPS != "" {
		t.Fatalf("devnull configuration: %+v %v", got, err)
	}
}

func TestGoDiscoveryConfigFileAndIsolation(t *testing.T) {
	userCertFixture := readPipFixture(t, "config/user-cert.conf")
	customFixture := readPipFixture(t, "config/custom.conf")
	duplicateProxyFixture := readPipFixture(t, "config/duplicate-proxy.conf")
	manager := goDiscoveryPip(t)
	writePipFixture(t, filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "pip", "pip.conf"), userCertFixture)
	explicit := filepath.Join(t.TempDir(), "custom.conf")
	writePipFixture(t, explicit, customFixture)
	t.Setenv("PIP_CONFIG_FILE", explicit)
	t.Setenv("PIP_CERT", "/environment.pem")
	for _, test := range []struct {
		args []string
		cert string
	}{
		{[]string{"wheel", "project"}, "/environment.pem"},
		{[]string{"--isolated", "wheel", "project"}, ""},
		{[]string{"--isolated", "download", "project"}, ""},
	} {
		got, err := manager.settings(test.args)
		if err != nil {
			t.Fatal(err)
		}
		if got.Cert != test.cert || got.HTTPS != "http://custom.example" || !slices.Equal(got.TrustedHosts, []string{"first.example", "second.example:443"}) {
			t.Fatalf("%v: %+v", test.args, got)
		}
	}
	writePipFixture(t, explicit, duplicateProxyFixture)
	if _, err := readPipConfig(filepath.Dir(filepath.Dir(manager.executable)), false); err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), explicit) {
		t.Fatalf("unsafe config diagnostic: %v", err)
	}
}

func TestGoDiscoveryProxyAndCertificatePrecedenceByVersion(t *testing.T) {
	for _, test := range []struct {
		version  pm.Version
		want     string
		fallback bool
	}{
		{pm.Version{Major: 22, Minor: 2, Patch: 2}, "http://standard.example", true},
		{pm.Version{Major: 25, Minor: 3}, "http://standard.example", true},
		{pm.Version{Major: 26, Minor: 1}, "http://standard.example", true},
		{pm.Version{Major: 26, Minor: 2}, "http://explicit.example", false},
	} {
		t.Run(test.version.String(), func(t *testing.T) {
			manager := goDiscoveryPip(t)
			manager.version = test.version
			t.Setenv("HTTPS_PROXY", "http://standard.example")
			t.Setenv("PIP_PROXY", "http://explicit.example")
			t.Setenv("PIP_CERT", "/pip.pem")
			t.Setenv("REQUESTS_CA_BUNDLE", "/requests.pem")
			t.Setenv("NO_PROXY", "*")
			got, err := manager.settings([]string{"download", "project"})
			if err != nil {
				t.Fatal(err)
			}
			cert := "/pip.pem"
			if test.fallback {
				cert = "/requests.pem"
			}
			if got.HTTPS != test.want || got.Cert != cert {
				t.Fatalf("routing/trust: %+v", got)
			}
			target, _ := url.Parse("https://registry.example/project.whl")
			selected, err := pipProxyForURL(got)(target)
			if err != nil || selected == nil || selected.String() != "http://explicit.example" {
				t.Fatalf("explicit fallback: %v %v", selected, err)
			}
		})
	}
}

func TestGoDiscoveryExplicitArguments(t *testing.T) {
	targetFixture := readPipFixture(t, "config/target.conf")
	manager := goDiscoveryPip(t)
	artifact := "https://user:password@files.example/owner's/project-1.0-py3-none-any.whl#sha256=123"
	args := []string{"--timeout=1", "--proxy", "http://proxy.example", "download", "--index-url", "https://index.example/simple/", "--extra-index-url", "https://extra.example/simple", "--trusted-host=first.example", "--trusted-host", "second.example", "--", artifact}
	got, err := manager.settings(args)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got.Indexes, "https://index.example/simple/") || !slices.Contains(got.Indexes, "https://extra.example/simple") || !slices.Contains(got.Direct, artifact) {
		t.Fatalf("explicit source context: %+v", got)
	}
	if !slices.Equal(got.TrustedHosts, []string{"first.example", "second.example"}) {
		t.Fatalf("repeated trust: %q", got.TrustedHosts)
	}
	t.Setenv("PIP_CONFIG_FILE", "")
	if err := os.Unsetenv("PIP_CONFIG_FILE"); err != nil {
		t.Fatal(err)
	}
	targetPrefix := t.TempDir()
	writePipFixture(t, filepath.Join(targetPrefix, "pip.conf"), targetFixture)
	got, err = manager.settings([]string{"--python", targetPrefix, "download", "project"})
	if err != nil || got.HTTPS != "http://target.example" {
		t.Fatalf("--python site config: %+v %v", got, err)
	}
}

func TestGoDiscoveryDirectURLMarkerAndEncodingQuery(t *testing.T) {
	manager := goDiscoveryPip(t)
	base := "https://private.example/project-1.0.tar.gz"
	for _, argument := range []string{base + "; python_version >= '3'", "project @ " + base + "; python_version >= '3'", base + "?encoding=source", "HTTPS://private.example/project-1.0.tar.gz"} {
		expected := base
		if strings.Contains(argument, "?encoding=") {
			expected = base + "?encoding=source"
		}
		if strings.HasPrefix(argument, "HTTPS://") {
			expected = argument
		}
		got, err := manager.settings([]string{"download", argument})
		if err != nil || !slices.Contains(got.Direct, expected) {
			t.Fatalf("%q: %q %v", argument, got.Direct, err)
		}
	}
}

func TestGoDiscoveryConfigNormalizesLongOptionsAndAliases(t *testing.T) {
	aliasesFixture := readPipFixture(t, "config/aliases.conf")
	manager := goDiscoveryPip(t)
	name := filepath.Join(t.TempDir(), "pip.conf")
	writePipFixture(t, name, aliasesFixture)
	t.Setenv("PIP_CONFIG_FILE", name)
	got, err := manager.settings([]string{"download", "project"})
	if err != nil || got.HTTPS != "http://original.example" || got.Cert != "/custom.pem" || !slices.Contains(got.Indexes, "https://private.example/packages/") {
		t.Fatalf("config aliases: %+v %v", got, err)
	}
}

func TestGoDiscoveryCannotDisableInterceptionWhenVersionIsUnknown(t *testing.T) {
	manager := goDiscoveryPip(t)
	manager.version = pm.Version{}
	manager.versionErr = errors.New("unavailable version")
	if _, err := manager.settings([]string{"--proxy", "http://original.example", "install", "https://private.example/project-1.0.tar.gz"}); err == nil {
		t.Fatal("unknown compatibility became a pass-through invocation")
	}
}

func TestGoDiscoveryPythonTargetCanComeFromConfigurationOrEnvironment(t *testing.T) {
	targetFixture := readPipFixture(t, "config/target.conf")
	pythonTargetFixture := readPipFixture(t, "config/python-target.conf.tmpl")
	for _, source := range []string{"environment", "configuration"} {
		manager := goDiscoveryPip(t)
		t.Setenv("PIP_CONFIG_FILE", "")
		if err := os.Unsetenv("PIP_CONFIG_FILE"); err != nil {
			t.Fatal(err)
		}
		target := t.TempDir()
		writePipFixture(t, filepath.Join(target, "pip.conf"), targetFixture)
		if source == "environment" {
			t.Setenv("PIP_PYTHON", target)
		} else {
			writePipFixture(t, filepath.Join(filepath.Dir(filepath.Dir(manager.executable)), "pip.conf"), fmt.Sprintf(pythonTargetFixture, target))
		}
		got, err := manager.settings([]string{"download", "project"})
		if err != nil || got.HTTPS != "http://target.example" {
			t.Fatalf("%s selected wrong prefix: %+v %v", source, got, err)
		}
	}
}

func TestRequirementsFilesAreLeftToPip(t *testing.T) {
	manager := goDiscoveryPip(t)
	requirements := filepath.Join(t.TempDir(), "requirements.txt")
	writePipFixture(t, requirements, readPipFixture(t, "requirements.txt"))
	for _, option := range []string{"-r", "--requirement", "-c", "--constraint", "--build-constraint"} {
		got, err := manager.settings([]string{"download", option, requirements})
		if err != nil {
			t.Fatal(err)
		}
		if len(got.TrustedHosts) != 0 || !slices.Equal(got.Indexes, []string{"https://pypi.org/simple"}) || len(got.Direct) != 0 {
			t.Fatalf("%s read requirements settings: %+v", option, got)
		}
		// A directory cannot be parsed as a requirements file; SCFW must leave it alone.
		if _, err := manager.settings([]string{"download", option, t.TempDir()}); err != nil {
			t.Fatalf("%s opened its file: %v", option, err)
		}
	}
}
