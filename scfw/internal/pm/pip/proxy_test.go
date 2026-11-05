// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestProxyOptionsExpandsCertificatePaths(t *testing.T) {
	configuration := readPipFixture(t, "config/home-relative-certs.conf")
	manager := goDiscoveryPip(t)
	registry := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 {
			t.Error("upstream client certificate missing")
			http.Error(w, "client certificate missing", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "authenticated")
	}))
	registry.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	registry.StartTLS()
	defer registry.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw})
	privateKey, err := x509.MarshalPKCS8PrivateKey(registry.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	client := append(slices.Clone(certificate), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})...)
	home := os.Getenv("HOME")
	for name, data := range map[string][]byte{"ca.pem": certificate, "client.pem": client} {
		if err := os.WriteFile(filepath.Join(home, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	caDirectory := filepath.Join(home, "ca-directory")
	if err := os.Mkdir(caDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "ca.pem"), filepath.Join(caDirectory, "01234567.0")); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"command", "equals", "environment", "configuration", "absolute", "directory command", "directory environment", "directory requests"} {
		t.Run(source, func(t *testing.T) {
			args := []string{"download", "project"}
			switch source {
			case "command":
				args = append([]string{"--cert", "~/ca.pem", "--client-cert", "~/client.pem"}, args...)
			case "equals":
				args = append(args, "--cert=~/ca.pem", "--client-cert=~/client.pem")
			case "environment":
				t.Setenv("PIP_CERT", "~/ca.pem")
				t.Setenv("PIP_CLIENT_CERT", "~/client.pem")
			case "configuration":
				path := filepath.Join(t.TempDir(), "pip.conf")
				writePipFixture(t, path, configuration)
				t.Setenv("PIP_CONFIG_FILE", path)
			case "absolute":
				args = append(args, "--cert", filepath.Join(home, "ca.pem"), "--client-cert", filepath.Join(home, "client.pem"))
			case "directory command", "directory environment", "directory requests":
				args = append(args, "--client-cert", "~/client.pem")
				switch source {
				case "directory command":
					args = append(args, "--cert", "~/ca-directory")
				case "directory environment":
					t.Setenv("PIP_CERT", "~/ca-directory")
				case "directory requests":
					t.Setenv("REQUESTS_CA_BUNDLE", "~/ca-directory")
				}
			}
			options, err := manager.ProxyOptions(args)
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{TLSClientConfig: options.UpstreamTLS}
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport}).Get(registry.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || string(body) != "authenticated" {
				t.Fatalf("upstream status=%d body=%q error=%v", response.StatusCode, body, err)
			}
		})
	}
}

func realPip(t *testing.T) Pip {
	t.Helper()
	executable, err := exec.LookPath("pip3")
	if err != nil {
		t.Skip("pip3 required for pip integration tests")
	}
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY", "PIP_PROXY", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CERT", "PIP_CLIENT_CERT", "PIP_TRUSTED_HOST"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PIP_CONFIG_FILE", os.DevNull)
	t.Setenv("scfw_test_proxy", "unused")
	return Pip{executable: executable}
}

func TestEffectiveProxySettings(t *testing.T) {
	pip := realPip(t)
	for _, tt := range []struct {
		name        string
		env         map[string]string
		args        []string
		http, https string
	}{
		{name: "direct", args: []string{"install", "example"}},
		{name: "standard", env: map[string]string{"HTTP_PROXY": "http://upper:secret@proxy.example:80", "https_proxy": "https://secure:secret@proxy.example:443"}, args: []string{"download", "example"}, http: "http://upper:secret@proxy.example:80", https: "https://secure:secret@proxy.example:443"},
		{name: "lowercase wins", env: map[string]string{"HTTP_PROXY": "http://upper.example", "http_proxy": "http://lower.example"}, args: []string{"wheel", "example"}, http: "http://lower.example"},
		{name: "all proxy", env: map[string]string{"ALL_PROXY": "http://all.example"}, args: []string{"install", "example"}, http: "http://all.example", https: "http://all.example"},
		{name: "pip override", env: map[string]string{"PIP_PROXY": "http://pip:secret@proxy.example"}, args: []string{"install", "example"}, http: "http://pip:secret@proxy.example", https: "http://pip:secret@proxy.example"},
		{name: "global option", env: map[string]string{"PIP_PROXY": "http://pip.example"}, args: []string{"--proxy=http://cli:secret@proxy.example", "--timeout", "1", "download", "-r", "requirements.txt"}, http: "http://cli:secret@proxy.example", https: "http://cli:secret@proxy.example"},
		{name: "isolated", env: map[string]string{"PIP_PROXY": "http://ignored.example"}, args: []string{"--isolated", "install", "example"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.env {
				t.Setenv(key, value)
			}
			got, err := pip.UpstreamProxy(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			if got.HTTPProxy != tt.http || got.HTTPSProxy != tt.https {
				t.Fatalf("unexpected upstream settings: HTTP=%q HTTPS=%q", got.HTTPProxy, got.HTTPSProxy)
			}
		})
	}
}

func TestPipConfigReadOnly(t *testing.T) {
	readOnlyFixture := readPipFixture(t, "config/read-only.conf")
	pip := realPip(t)
	path := filepath.Join(t.TempDir(), "pip.conf")
	content := readOnlyFixture
	if err := os.WriteFile(path, []byte(content), 0400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIP_CONFIG_FILE", path)
	for _, cmd := range []string{"install", "download", "wheel"} {
		got, err := pip.UpstreamProxy([]string{"--disable-pip-version-check", cmd, "example"})
		if err != nil {
			t.Fatal(err)
		}
		want := "http://global:password@proxy.example"
		if got.HTTPSProxy != want {
			t.Fatalf("%s did not preserve config proxy", cmd)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != content {
		t.Fatal("pip configuration changed")
	}
}

func TestProxyCommandPreservesArgumentsAndSuppliesOverrides(t *testing.T) {
	manager := realPip(t)
	command := []string{"--isolated", "download", "--proxy", "http://original.example", "project==1.0"}
	original := slices.Clone(command)
	config := proxy.ClientConfig{URL: "http://127.0.0.1:1234", CACertificatePath: "/private/ca.pem"}
	spec, err := manager.ProxyCommand(context.Background(), command, config)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Executable != manager.Executable() {
		t.Fatal("selected executable changed")
	}
	want := append(slices.Clone(original), "--proxy", config.URL, "--cert", config.CACertificatePath)
	if !slices.Equal(spec.Args, want) || !slices.Equal(command, original) {
		t.Fatalf("arguments changed: got %q", spec.Args)
	}
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "PIP_PROXY"} {
		if spec.EnvOverrides[key] != config.URL {
			t.Fatal("missing proxy override", key)
		}
	}
	for _, key := range []string{"PIP_CERT", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO"} {
		if spec.EnvOverrides[key] != config.CACertificatePath {
			t.Fatal("missing trust override", key)
		}
	}
}

func TestPipCommandFailureIsPreserved(t *testing.T) {
	pip := realPip(t)
	err, setupErr := proxy.Run(context.Background(), proxy.Options{}, []string{"--not-an-option"}, pip)
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	if err == nil {
		t.Fatal("manager failure lost")
	}
	if strings.Contains(err.Error(), "password") {
		t.Fatal("credential in error")
	}
}

func TestPipHelpRunsThroughProxy(t *testing.T) {
	manager := realPip(t)
	for _, args := range [][]string{{"help"}, {"help", "install"}, {"--help"}, {"install", "--help"}, {"--version"}} {
		commandErr, setupErr := proxy.Run(context.Background(), proxy.Options{}, args, manager)
		if commandErr != nil || setupErr != nil {
			t.Fatalf("%q failed: command=%v setup=%v", args, commandErr, setupErr)
		}
	}
}

func TestInvalidUpstreamNeverBecomesDirect(t *testing.T) {
	pip := realPip(t)
	t.Setenv("PIP_PROXY", "http://proxy.invalid:8080/%ZZ")
	if _, err := pip.UpstreamProxy([]string{"install", "example"}); err == nil {
		t.Fatal("invalid upstream accepted")
	}
	if _, err := pip.ProxyOptions([]string{"install", "example"}); err == nil {
		t.Fatal("invalid upstream accepted by proxy options")
	}
}

func TestOnlyDirectArtifactsBecomeArtifactContext(t *testing.T) {
	manager := realPip(t)
	artifact := "https://files.example/project-1.0-py3-none-any.whl"
	options, err := manager.PyPIClassifierOptions([]string{"download", "--no-index", "--find-links", t.TempDir(), "--find-links", "file:///tmp/wheels", "--find-links", "https://index.example/wheelhouse/", artifact})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pypi.NewRequestClassifier(options); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(options.DirectArtifactURLs, []string{artifact}) {
		t.Fatalf("unexpected source URLs: %q", options.DirectArtifactURLs)
	}
}

func TestExplicitProxyFallbackSurvivesNoProxy(t *testing.T) {
	manager := realPip(t)
	t.Setenv("PIP_PROXY", "http://explicit:secret@proxy.example:8080")
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")
	options, err := manager.ProxyOptions([]string{"download", "project"})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"https://registry.example/project.whl", "http://127.0.0.1/project.whl"} {
		target, err := url.Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		selected, err := options.ProxyForURL(target)
		if err != nil {
			t.Fatal(err)
		}
		if selected == nil || selected.String() != "http://explicit:secret@proxy.example:8080" {
			t.Fatal("NO_PROXY bypassed the explicit pip proxy")
		}
	}
}

func TestRequestsProxyBypass(t *testing.T) {
	for _, test := range []struct {
		target, pattern string
		bypass          bool
	}{
		{"https://index.example/path", ".example", true},
		{"https://index.example:8443/path", "index.example:443", false},
		{"https://index.example:8443/path", "index.example:8443", true},
		{"http://127.0.0.1/path", "", false},
		{"http://127.0.0.1/path", "127.0.0.0/8", true},
		{"https://index.example/path", "*", true},
		{"https://example.com/path", ".example.com", true},
		{"https://index.example/path", "foo,*", false},
		{"https://index.example/path", " * ", false},
		{"https://notexample.com/path", "example.com", false},
	} {
		target, err := url.Parse(test.target)
		if err != nil {
			t.Fatal(err)
		}
		if got := pipBypassesEnvironment(target, test.pattern, false); got != test.bypass {
			t.Fatalf("bypass(%s,%s)=%v", test.target, test.pattern, got)
		}
	}
}

func TestQuotedDirectArgumentsKeepTheirCompleteURL(t *testing.T) {
	manager := realPip(t)
	value := "https://user:password@files.example/owner's/project-1.0-py3-none-any.whl"
	for _, argument := range []string{value, "project @ " + value + ` ; python_version >= "3"`} {
		settings, err := manager.settings([]string{"download", "--no-index", argument})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(settings.Direct, value) {
			t.Fatalf("direct artifact context truncated: %q", settings.Direct)
		}
	}
}

func TestProxyOptionsAlwaysLoadTrust(t *testing.T) {
	manager := realPip(t)
	t.Setenv("PIP_CERT", filepath.Join(t.TempDir(), "missing-ca.pem"))
	t.Setenv("PIP_CLIENT_CERT", filepath.Join(t.TempDir(), "missing-client.pem"))
	t.Setenv("GIT_SSL_CAINFO", filepath.Join(t.TempDir(), "missing-git.pem"))
	for _, args := range [][]string{{"freeze", "--all"}, {"show", "pip"}, {"cache", "info"}, {"not-a-command"}, {"--help"}, {"--version"}} {
		if _, err := manager.ProxyOptions(args); err == nil {
			t.Fatalf("%q skipped loading configured trust", args)
		}
	}
}
