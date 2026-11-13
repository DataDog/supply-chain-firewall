// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func TestNpmRealPreflightArtifacts(t *testing.T) {
	executable, e := exec.LookPath("npm")
	if e != nil {
		t.Skip("npm unavailable")
	}
	manifest, e := os.ReadFile("testdata/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	if e = tw.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o644, Size: int64(len(manifest))}); e != nil {
		t.Fatal(e)
	}
	_, _ = tw.Write(manifest)
	markerSource, e := os.ReadFile("testdata/marker.js")
	if e != nil {
		t.Fatal(e)
	}
	_ = tw.WriteHeader(&tar.Header{Name: "package/marker.js", Mode: 0o644, Size: int64(len(markerSource))})
	_, _ = tw.Write(markerSource)
	_ = tw.Close()
	_ = gz.Close()
	archive := b.Bytes()
	digest := sha512.Sum512(archive)
	var mismatch atomic.Bool
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/opaque" || r.URL.Path == "/fixture/-/fixture-1.0.0.tgz" {
			_, _ = w.Write(archive)
			return
		}
		if r.URL.Path != "/fixture" {
			http.NotFound(w, r)
			return
		}
		var m map[string]any
		_ = json.Unmarshal(manifest, &m)
		if mismatch.Load() {
			delete(m, "scripts")
		}
		m["dist"] = map[string]any{"tarball": "https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz", "integrity": "sha512-" + base64.StdEncoding.EncodeToString(digest[:])}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "fixture", "dist-tags": map[string]string{"latest": "1.0.0"}, "time": map[string]string{"1.0.0": "2025-01-01T00:00:00Z"}, "versions": map[string]any{"1.0.0": m}})
	}))
	defer server.Close()
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("SCFW_TEST_MARKER", marker)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("npm_config_userconfig", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("npm_config_globalconfig", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("npm_config_registry", server.URL)
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("npm_config_cache", t.TempDir())
	for _, scenario := range []string{"install", "locked-install", "legacy-locked-install"} {
		for _, bad := range []bool{false, true} {
			name := scenario
			if bad {
				name += "/mismatch"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				root := npmProjectFixture(t, "project/registry-root")
				if e := os.WriteFile(filepath.Join(dir, "package.json"), []byte(root), 0o644); e != nil {
					t.Fatal(e)
				}
				t.Chdir(dir)
				args := []string{"install"}
				mismatch.Store(false)
				if scenario != "install" {
					child := exec.Command(executable, "install", "--package-lock-only", "--ignore-scripts", "--audit=false")
					if out, e := child.CombinedOutput(); e != nil {
						t.Fatalf("prepare lock: %v %s", e, out)
					}
				}
				if scenario == "legacy-locked-install" {
					locked, e := readNpmJSONFile("package-lock.json")
					if e != nil {
						t.Fatal(e)
					}
					entries, ok := locked["packages"].(map[string]any)
					if !ok {
						t.Fatal("native package lock has no resolved packages")
					}
					v1 := map[string]any{"name": "root", "version": "1.0.0", "lockfileVersion": 1, "requires": true, "dependencies": map[string]any{"fixture": entries["node_modules/fixture"]}}
					if e = writeNpmJSONFile("package-lock.json", v1); e != nil {
						t.Fatal(e)
					}
				}
				original, _ := os.ReadFile("package-lock.json")
				mismatch.Store(bad)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				n, e := NewNpm(ctx, "npm", executable)
				if e != nil {
					t.Fatal(e)
				}
				targets, results, e := n.ResolveVerifiedInstallTargets(ctx, args)
				if e != nil {
					t.Fatal(e)
				}
				if targets.Len() == 0 {
					t.Fatal("empty dry-run install targets")
				}
				found := false
				for _, result := range results {
					if result.Package.Name == "fixture" {
						found = true
						want := pm.ArtifactMatched
						if bad {
							want = pm.ArtifactMismatched
						}
						if result.Status != want {
							t.Fatalf("artifact = %+v", result)
						}
					}
				}
				if _, e := os.Stat(marker); !os.IsNotExist(e) {
					t.Fatal("lifecycle code ran during preflight")
				}
				if !found {
					t.Fatal("dry-run registry dependency was missed")
				}
				after, _ := os.ReadFile("package-lock.json")
				if !bytes.Equal(original, after) {
					t.Fatal("original lock changed")
				}
				if _, e := os.Stat("node_modules"); !os.IsNotExist(e) {
					t.Fatal("preflight installed into original project")
				}
			})
		}
	}
}
func TestNpmAuthScopeBoundaries(t *testing.T) {
	s := npmVerificationSettings{"//registry.example:_authToken": "secret", "//registry.example/private:_authToken": "private"}
	for _, c := range []struct{ url, want string }{{"https://registry.example/pkg", "Bearer secret"}, {"https://registry.example/private/pkg", "Bearer private"}, {"https://registry.example/private-other/pkg", "Bearer secret"}, {"https://registry.example/private%2Fother/pkg", "Bearer secret"}, {"https://registry.example.attacker.test/pkg", ""}} {
		u, _ := url.Parse(c.url)
		if got := s.authorization(u); got != c.want {
			t.Fatalf("credential scope %s: %q", c.url, got)
		}
	}
}
func TestNpmInstallCommandControls(t *testing.T) {
	args := insertNpmControls([]string{"install", "--", "fixture"}, "--ignore-scripts")
	if strings.Join(args, " ") != "install --ignore-scripts -- fixture" {
		t.Fatal(args)
	}
	for _, args := range [][]string{{"--production", "install", "fixture"}, {"--production", "null", "install", "fixture"}, {"--no-@scope:registry", "install", "fixture"}, {"--optional", "install", "fixture"}, {"--workspaces", "install", "fixture"}, {"--color", "always", "install", "fixture"}} {
		if !npmInstallCommandSupported(args) {
			t.Fatalf("union-boolean option bypass: %v", args)
		}
	}
	if !npmInstallCommandSupported([]string{"--fetch-retries", "2", "install", "fixture"}) {
		t.Fatal("global option bypass")
	}
	if !npmInstallCommandSupported([]string{"install", "--dry-run", "false"}) {
		t.Fatal("false dry-run bypass")
	}
	if npmInstallCommandSupported([]string{"install", "--dry-run=true"}) {
		t.Fatal("true dry-run must pass through")
	}
	if got := npmCLIConfig([]string{"--reg", "https://private.example/", "install"})["registry"]; got != "https://private.example/" {
		t.Fatal("abbreviated config option lost")
	}
	if npmInstallCommandSupported([]string{"run", "install"}) {
		t.Fatal("npm run must not enter preflight")
	}
	if npmInstallCommandSupported([]string{"exec", "tool", "install"}) {
		t.Fatal("npm exec must not enter preflight")
	}

}

func TestNpmVerificationRequestSettings(t *testing.T) {
	if !npmInstallCommandSupported([]string{"--no-proxy", "install", "fixture"}) {
		t.Fatal("negated proxy option bypass")
	}
	settings := npmVerificationSettings{}
	if e := readNpmConfig("testdata/array-ca.npmrc", settings); e != nil {
		t.Fatal(e)
	}
	if settings["ca"] != "first\nsecond" {
		t.Fatal("CA array was lost")
	}
	if settings.registry("@my_scope/pkg") != "https://private.example/" {
		t.Fatal("registry scope was changed")
	}
	u, _ := url.Parse("https://registry.example/nested/pkg")
	if settings.authorization(u) != "Bearer fixture-token" {
		t.Fatal("non-credential key shadowed authentication")
	}
	if _, e := settings.transportOptions(); e == nil {
		t.Fatal("invalid explicit CA must never fall back to system trust")
	}

}

func npmProjectFixture(t *testing.T, name string) string {
	t.Helper()
	file, e := os.ReadFile("testdata/responses.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixtures map[string]json.RawMessage
	if e = json.Unmarshal(file, &fixtures); e != nil {
		t.Fatal(e)
	}
	body, ok := fixtures[name]
	if !ok {
		t.Fatalf("unknown npm project fixture %s", name)
	}
	return string(body)
}

func TestNpmArtifactURLMapping(t *testing.T) {
	for _, c := range []struct {
		major                 int
		setting, source, want string
	}{{10, "", "https://registry.npmjs.org/pkg/-/pkg-1.tgz?sig=original", "https://mirror.example/pkg/-/pkg-1.tgz"}, {7, "", "https://registry.npmjs.org/pkg/-/pkg-1.tgz?sig=original", "https://mirror.example/npm/pkg/-/pkg-1.tgz?sig=original"}, {10, "never", "https://registry.npmjs.org/pkg/-/pkg-1.tgz?sig=original", "https://registry.npmjs.org/pkg/-/pkg-1.tgz?sig=original"}, {10, "", "https://cdn.example/archive?sig=private", "https://cdn.example/archive?sig=private"}, {10, "", "HTTPS://REGISTRY.NPMJS.ORG:443/a/../pkg/-/pkg-1.tgz?sig=original", "https://mirror.example/pkg/-/pkg-1.tgz"}, {10, "always", "https://cdn.example/archive?sig=private", "https://mirror.example/archive"}} {
		n := Npm{version: pm.Version{Major: c.major}}
		mapper := n.artifactURLMapperForSettings(npmVerificationSettings{"registry": "https://mirror.example/npm/", "replace-registry-host": c.setting})
		got, e := mapper(c.source)
		if e != nil || got != c.want {
			t.Fatalf("npm %d mapping=%s error=%v want=%s", c.major, got, e, c.want)
		}
	}
}

func TestNpmHTTPSourceAndNativeURLForm(t *testing.T) {
	if !npmHTTPSource("HTTPS://registry.example/pkg.tgz") {
		t.Fatal("uppercase HTTP scheme lost verification")
	}
	if npmHTTPSource("git+https://registry.example/repo") {
		t.Fatal("Git became a registry artifact")
	}
	for _, c := range []struct{ source, want string }{{"https://EXAMPLE.com:443/a/%2e%2e/pkg?sig=keep#ignored", "https://example.com/pkg?sig=keep"}, {"http://example.com/a//../pkg", "http://example.com/a/pkg"}, {"https://example.com/pkg/%2Fname?token=keep", "https://example.com/pkg/%2Fname?token=keep"}} {
		got, e := canonicalNpmURL(c.source)
		if e != nil || got != c.want {
			t.Fatalf("native URL=%s %v want=%s", got, e, c.want)
		}
	}
}

func TestNpmURLRejectsAmbiguousNativeHosts(t *testing.T) {
	for _, source := range []string{"https://0177.0.0.1/pkg", "https://0x7f000001/pkg", "https://2130706433/pkg"} {
		if _, e := canonicalNpmURL(source); e == nil {
			t.Fatalf("ambiguous numeric host accepted: %s", source)
		}
	}
	got, e := canonicalNpmURL("https://EXAMPLE.com:00443/pkg?sig=keep")
	if e != nil || got != "https://example.com/pkg?sig=keep" {
		t.Fatalf("default port mapping=%s %v", got, e)
	}
}

func TestNpmNetworkPathReplacementFailsClosed(t *testing.T) {
	n := Npm{version: pm.Version{Major: 10}}
	mapper := n.artifactURLMapperForSettings(npmVerificationSettings{"registry": "https://mirror.example/"})
	if _, e := mapper("https://registry.npmjs.org//cdn.example/fixture.tgz"); e == nil {
		t.Fatal("network-path source was verified at a different origin")
	}

}

func TestNpmVerificationLoadsConfigWithoutPackageManifest(t *testing.T) {
	n := fixtureNpm(t)
	// Exclude process-level npm settings so the project fixture is authoritative.
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(strings.ToLower(key), "npm_config_") {
			t.Setenv(key, value)
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("npm_config_userconfig", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("npm_config_globalconfig", filepath.Join(t.TempDir(), "absent"))
	fixture, err := os.ReadFile("testdata/request-settings.npmrc")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, ".npmrc"), fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	settings, err := n.verificationSettings([]string{"install", "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if settings["registry"] != "https://registry.example/" || settings["proxy"] != "http://proxy.example:8080" {
		t.Fatal("project network configuration was discarded without package.json")
	}
	if _, err := settings.transportOptions(); err == nil {
		t.Fatal("explicit invalid CA was replaced with system trust")
	}
}
