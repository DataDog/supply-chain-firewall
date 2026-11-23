// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
)

// yarnGenerations are the Yarn releases the archive cases run against. Yarn 4
// renamed Classic's --frozen-lockfile to --immutable.
var yarnGenerations = []struct {
	name       string
	variable   string
	rcName     string
	frozenFlag string
}{
	{"classic", "SCFW_TEST_YARN_CLASSIC", ".yarnrc", "--frozen-lockfile"},
	{"berry", "SCFW_TEST_YARN_BERRY", ".yarnrc.yml", "--immutable"},
}

// yarnArchiveProject enters a project for one generation, whose rc file the
// caller compares after the run.
func yarnArchiveProject(t *testing.T, generation string, registry *npmTestRegistry) (dir, rc string) {
	t.Helper()
	if generation == "classic" {
		rc = classicYarnrc(registry, "")
		return newYarnTestProject(t, ".yarnrc", rc), rc
	}
	rc = berryYarnrc(registry, "nodeLinker: node-modules\n")
	return newBerryTestProject(t, rc), rc
}

// yarnAddArguments returns the `yarn add` command for the tarball at url:
// Yarn Classic accepts the bare URL, Yarn 4 wants the package aliased to it.
func yarnAddArguments(generation, url string) []string {
	if generation == "classic" {
		return []string{"add", url}
	}
	return []string{"add", "lab-pkg@" + url}
}

// yarnAddDependency returns the `yarn add` command for a non-URL dependency
// reference, aliased for Yarn 4 the way yarnAddArguments aliases URLs.
func yarnAddDependency(generation, ref string) []string {
	if generation == "classic" {
		return []string{"add", ref}
	}
	return []string{"add", "lab-git-pkg@" + ref}
}

// startYarnArchiveServer starts a TLS server playing a tarball origin the rc
// helpers trust; its handler counts its own downloads.
func startYarnArchiveServer(t *testing.T, handler http.HandlerFunc) *npmTestRegistry {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	certificate, caPEM, _ := proxyTLSIdentity(t)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	registry := &npmTestRegistry{URL: "https://localhost:" + server.URL[strings.LastIndex(server.URL, ":")+1:], CAPEM: string(caPEM)}
	registry.CAPath = filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(registry.CAPath, []byte(registry.CAPEM), 0600); err != nil {
		t.Fatal(err)
	}
	return registry
}

// yarnProjectFiles is the manifest and lockfile state before a command, which
// a failed command must leave alone.
type yarnProjectFiles struct {
	manifest    []byte
	lockfile    []byte
	hasLockfile bool
}

func readYarnProjectFiles(t *testing.T, dir string) yarnProjectFiles {
	t.Helper()
	files := yarnProjectFiles{}
	var err error
	if files.manifest, err = os.ReadFile(filepath.Join(dir, "package.json")); err != nil {
		t.Fatal(err)
	}
	if files.lockfile, err = os.ReadFile(filepath.Join(dir, "yarn.lock")); err == nil {
		files.hasLockfile = true
	}
	return files
}

// yarnArchiveDownloads returns the tarball downloads a run makes: the
// download is forwarded before its response is judged, and a refused one is
// asked for again only by Yarn Classic, whose request manager retries a
// failed GET up to its hardcoded limit of five attempts.
func yarnArchiveDownloads(generation string, blocked bool) int32 {
	if !blocked || generation != "classic" {
		return 1
	}
	return 5
}

// assertYarnArchiveRun checks the shared end state of every archive case: one
// evaluation with the expected source, the package present only when the run
// succeeded, a failed command leaving the manifest, lockfile, and rc file as
// they were, and the invocation proxy cleaned up.
func assertYarnArchiveRun(t *testing.T, run yarnProxyRun, dir, rcName, rc, packageDir string, before yarnProjectFiles, wantSources []string, failed bool) {
	t.Helper()
	if !failed {
		if _, err := os.Stat(filepath.Join(dir, "node_modules", packageDir, "package.json")); err != nil {
			t.Fatalf("package %s not installed: %v", packageDir, err)
		}
	} else if _, err := os.Stat(filepath.Join(dir, "node_modules", packageDir)); err == nil {
		t.Fatalf("blocked package %s was installed", packageDir)
	}
	if run.calls != 1 || !slices.Equal(run.sources, wantSources) {
		t.Fatalf("evaluations = %d, sources = %v, want 1 of %v", run.calls, run.sources, wantSources)
	}
	if failed {
		manifest, err := os.ReadFile(filepath.Join(dir, "package.json"))
		if err != nil || !slices.Equal(manifest, before.manifest) {
			t.Fatalf("a failed command changed package.json: %q (error %v)", manifest, err)
		}
		lockfile, lockErr := os.ReadFile(filepath.Join(dir, "yarn.lock"))
		if (lockErr == nil) != before.hasLockfile || (lockErr == nil && !slices.Equal(lockfile, before.lockfile)) {
			t.Fatalf("a failed command changed yarn.lock: %q (error %v)", lockfile, lockErr)
		}
	}
	if after, err := os.ReadFile(filepath.Join(dir, rcName)); err != nil || string(after) != rc {
		t.Fatalf("%s changed: %q (error %v)", rcName, after, err)
	}
	assertProxyCleaned(t, run.config)
}

// TestYarnArchiveDependencies covers the tarball-shaped downloads Yarn makes
// outside the registry layout, for both generations: a direct tarball URL, a
// GitHub-codeload-shaped git archive URL, and a lockfile that resolves a
// package to such a URL.
func TestYarnArchiveDependencies(t *testing.T) {
	for _, generation := range yarnGenerations {
		for _, test := range []struct {
			name string
			// addCommand is the `yarn add` command that fetches the package.
			addCommand func(registry *npmTestRegistry) []string
			// runCommand overrides the command under test (lockfile installs).
			runCommand func() []string
			seed       bool
			// source is the URL the package is reported from.
			source func(registry *npmTestRegistry) string
			failed bool
		}{
			{name: "url-allow",
				addCommand: func(registry *npmTestRegistry) []string {
					return yarnAddArguments(generation.name, registry.URL+npmDirectTarballPath)
				},
				source: func(registry *npmTestRegistry) string { return registry.URL + npmDirectTarballPath }},
			{name: "url-block",
				addCommand: func(registry *npmTestRegistry) []string {
					return yarnAddArguments(generation.name, registry.URL+npmDirectTarballPath)
				},
				source: func(registry *npmTestRegistry) string { return registry.URL + npmDirectTarballPath }, failed: true},
			{name: "git-archive-allow",
				addCommand: func(registry *npmTestRegistry) []string {
					return yarnAddArguments(generation.name, registry.URL+npmGitArchivePath)
				},
				source: func(registry *npmTestRegistry) string { return registry.URL + npmGitArchivePath }},
			{name: "git-archive-block",
				addCommand: func(registry *npmTestRegistry) []string {
					return yarnAddArguments(generation.name, registry.URL+npmGitArchivePath)
				},
				source: func(registry *npmTestRegistry) string { return registry.URL + npmGitArchivePath }, failed: true},
			{name: "lockfile-frozen-block",
				addCommand: func(registry *npmTestRegistry) []string {
					return yarnAddArguments(generation.name, registry.URL+npmDirectTarballPath)
				},
				runCommand: func() []string { return []string{"install", generation.frozenFlag} }, seed: true,
				source: func(registry *npmTestRegistry) string { return registry.URL + npmDirectTarballPath }, failed: true},
			{name: "lockfile-install-allow",
				addCommand: func(registry *npmTestRegistry) []string {
					return yarnAddArguments(generation.name, registry.URL+npmDirectTarballPath)
				},
				runCommand: func() []string { return []string{"install"} }, seed: true,
				source: func(registry *npmTestRegistry) string { return registry.URL + npmDirectTarballPath }},
		} {
			t.Run(generation.name+"/"+test.name, func(t *testing.T) {
				executable := yarnTestExecutable(t, generation.variable)
				registry := startNpmRegistry(t)
				dir, rc := yarnArchiveProject(t, generation.name, registry)
				if test.seed {
					seedYarnLockfile(t, executable, dir, test.addCommand(registry)...)
				}
				before := readYarnProjectFiles(t, dir)
				args := test.addCommand(registry)
				if test.runCommand != nil {
					args = test.runCommand()
				}
				downloads := registry.TarballHits.Load()
				outcome := evaluation.OutcomeAllow
				if test.failed {
					outcome = evaluation.OutcomeBlock
				}
				run := runYarnThroughProxy(t, executable, args, outcome)
				if test.failed {
					assertYarnFailed(t, run)
				} else {
					assertYarnSucceeded(t, run)
				}
				if hits := registry.TarballHits.Load() - downloads; hits != yarnArchiveDownloads(generation.name, test.failed) {
					t.Fatalf("tarball downloads = %d, want %d", hits, yarnArchiveDownloads(generation.name, test.failed))
				}
				assertYarnArchiveRun(t, run, dir, generation.rcName, rc, "lab-pkg", before, []string{test.source(registry)}, test.failed)
			})
		}
	}
}

// TestYarnRedirectedArchiveDependencies covers a tarball URL whose response
// redirects to a suffix-less path no URL pattern recognizes: the redirect
// target must still be evaluated, with the target URL as the source.
func TestYarnRedirectedArchiveDependencies(t *testing.T) {
	const redirectPath = "/redirects/lab-pkg.tgz"
	const targetPath = "/downloads/lab-pkg-archive"
	tarball := npmTarball(t)
	for _, generation := range yarnGenerations {
		for _, test := range []struct {
			name   string
			failed bool
		}{{"allow", false}, {"block", true}} {
			t.Run(generation.name+"/"+test.name, func(t *testing.T) {
				executable := yarnTestExecutable(t, generation.variable)
				var hits atomic.Int32
				registry := startYarnArchiveServer(t, func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case redirectPath:
						hits.Add(1)
						http.Redirect(w, r, targetPath, http.StatusFound)
					case targetPath:
						// No URL pattern matches the path and the body is served
						// as a generic download, so only the recorded redirect
						// (or, once K9CODESEC-9784 lands, the response headers)
						// identifies the target as an archive.
						hits.Add(1)
						w.Header().Set("Content-Type", "application/octet-stream")
						_, _ = w.Write(tarball)
					default:
						http.NotFound(w, r)
					}
				})
				dir, rc := yarnArchiveProject(t, generation.name, registry)
				before := readYarnProjectFiles(t, dir)
				outcome := evaluation.OutcomeAllow
				if test.failed {
					outcome = evaluation.OutcomeBlock
				}
				run := runYarnThroughProxy(t, executable, yarnAddArguments(generation.name, registry.URL+redirectPath), outcome)
				if test.failed {
					assertYarnFailed(t, run)
				} else {
					assertYarnSucceeded(t, run)
				}
				wantRequests := int32(2)
				if test.failed && generation.name == "classic" {
					// Classic asks again for a refused fetch, each of its
					// attempts a redirect and its target.
					wantRequests = 10
				}
				if hits := hits.Load(); hits != wantRequests {
					t.Fatalf("requests = %d, want %d", hits, wantRequests)
				}
				assertYarnArchiveRun(t, run, dir, generation.rcName, rc, "lab-pkg", before, []string{registry.URL + targetPath}, test.failed)
			})
		}
	}
}

// TestYarnForcedPartialAndCachedArchives covers responses Yarn itself never
// triggers for tarball downloads, forced by the origin: the first download
// answers 206 with the complete body, or 304, and later requests a full
// response. SCFW must re-fetch a complete copy, evaluate it, and only then
// release the original response.
func TestYarnForcedPartialAndCachedArchives(t *testing.T) {
	tarball := npmTarball(t)
	for _, generation := range yarnGenerations {
		for _, status := range []struct {
			name string
			code int
			// A 304 answers a first download with no body at all: after the
			// evaluated re-fetch, Yarn's own empty-body handling fails the
			// install even when the package is allowed.
			succeeds bool
		}{{"partial", http.StatusPartialContent, true}, {"cached", http.StatusNotModified, false}} {
			for _, test := range []struct {
				name   string
				failed bool
			}{{"allow", false}, {"block", true}} {
				t.Run(generation.name+"/"+status.name+"-"+test.name, func(t *testing.T) {
					if generation.name == "berry" && status.code == http.StatusNotModified && !test.failed {
						// Yarn 4's fetch waits for body bytes a bodyless 304
						// never promises, so an allowed one never ends the
						// command; the blocked case proves the evaluated
						// re-fetch, and the partial case the allowed one.
						t.Skip("Yarn 4 does not terminate on a bodyless 304")
					}
					executable := yarnTestExecutable(t, generation.variable)
					var requests atomic.Int32
					var conditionalMutex sync.Mutex
					var conditional []string
					registry := startYarnArchiveServer(t, func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != npmDirectTarballPath {
							http.NotFound(w, r)
							return
						}
						if requests.Add(1) == 1 {
							// Yarn asks for no range or conditional content;
							// recording its headers proves the forced response
							// is what exercises the hook.
							conditionalMutex.Lock()
							for _, name := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
								if r.Header.Get(name) != "" {
									conditional = append(conditional, name)
								}
							}
							conditionalMutex.Unlock()
							if status.code == http.StatusPartialContent {
								w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(tarball)-1, len(tarball)))
								w.WriteHeader(http.StatusPartialContent)
								_, _ = w.Write(tarball)
							} else {
								w.WriteHeader(http.StatusNotModified)
							}
							return
						}
						w.Header().Set("Content-Type", "application/octet-stream")
						_, _ = w.Write(tarball)
					})
					dir, rc := yarnArchiveProject(t, generation.name, registry)
					before := readYarnProjectFiles(t, dir)
					outcome := evaluation.OutcomeAllow
					if test.failed {
						outcome = evaluation.OutcomeBlock
					}
					run := runYarnThroughProxy(t, executable, yarnAddArguments(generation.name, registry.URL+npmDirectTarballPath), outcome)
					failed := test.failed || !status.succeeds
					if failed {
						assertYarnFailed(t, run)
					} else {
						assertYarnSucceeded(t, run)
					}
					conditionalMutex.Lock()
					sent := slices.Clone(conditional)
					conditionalMutex.Unlock()
					if len(sent) != 0 {
						t.Fatalf("Yarn sent conditional headers %v; a forced response is no longer what exercises the hook", sent)
					}
					wantRequests := int32(2)
					if test.failed && generation.name == "classic" {
						// Only the first download is answered with the forced
						// status, so the re-fetch happens once and each of
						// Classic's retries is one more full response.
						wantRequests = 6
					}
					if served := requests.Load(); served != wantRequests {
						t.Fatalf("requests = %d, want %d: Yarn's download and the evaluated full re-fetch", served, wantRequests)
					}
					assertYarnArchiveRun(t, run, dir, generation.rcName, rc, "lab-pkg", before, []string{registry.URL + npmDirectTarballPath}, failed)
				})
			}
		}
	}
}

// yarnGitHubOrigin stands in for every host a github: dependency touches: one
// TLS endpoint, reached through a chained proxy whose CONNECTs are all
// rewritten to its listener, so its certificate names them all and its handler
// serves them all. The dependency's repository has no dependencies, so no
// registry request is expected; one that arrives fails the test with a 404.
type yarnGitHubOrigin struct {
	registry                                   *npmTestRegistry
	owner, repo, sha, ref, tarballURL, address string
	codeload, packs                            atomic.Int32
}

func (o *yarnGitHubOrigin) repository() string {
	return "/" + o.owner + "/" + o.repo
}

// startYarnGitHubOrigin serves a bare repository built from manifest at the
// GitHub hosts Yarn contacts for a github: dependency.
func startYarnGitHubOrigin(t *testing.T, manifest string) *yarnGitHubOrigin {
	t.Helper()
	spec, sha, _ := npmGitDependencyFrom(t, manifest)
	origin := &yarnGitHubOrigin{owner: "acme", repo: "lab-repo", sha: sha}
	root := t.TempDir()
	bare := filepath.Join(root, origin.owner, origin.repo+".git")
	if err := os.MkdirAll(filepath.Dir(bare), 0700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "clone", "-q", "--bare", strings.TrimPrefix(spec, "git+file://"), bare).CombinedOutput(); err != nil {
		t.Fatalf("git fixture: %v %s", err, output)
	}
	// A git archive carries the single root directory of the pinned commit,
	// the shape GitHub serves codeload tarballs in.
	archive, err := exec.Command("git", "-C", bare, "archive", "--format=tar.gz", "--prefix="+origin.repo+"-"+sha+"/", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	refs := cgi.Handler{Path: git, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	manifestBody := []byte(readProxyFixture(t, manifest))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames:    []string{"localhost", "github.com", "codeload.github.com", "raw.githubusercontent.com"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:        true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := strings.Cut(r.Host, ":")
		switch host {
		case "github.com":
			switch {
			case r.Method == http.MethodHead && r.URL.Path == origin.repository():
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodGet && r.URL.Path == origin.repository()+".git/info/refs":
				refs.ServeHTTP(w, r)
			case r.Method == http.MethodPost && r.URL.Path == origin.repository()+".git/git-upload-pack":
				// Yarn 4 reads a github: dependency's manifest through one
				// resolution clone before it fetches the commit archive; on
				// main that clone is the uninspected step PR #373 covers.
				// Once the archive has been requested, a pack is the clone
				// Yarn falls back to after a refused archive, which the
				// archive hook cannot see: refusing it keeps the archive this
				// test covers the only delivery path.
				origin.packs.Add(1)
				if origin.codeload.Load() != 0 {
					http.Error(w, "pack downloads refused", http.StatusForbidden)
					return
				}
				refs.ServeHTTP(w, r)
			case r.Method == http.MethodGet && r.URL.Path == origin.repository()+"/archive/"+origin.sha+".tar.gz":
				http.Redirect(w, r, origin.tarballURL, http.StatusFound)
			default:
				http.NotFound(w, r)
			}
		case "codeload.github.com":
			if r.Method != http.MethodGet || r.URL.Path != origin.repository()+"/tar.gz/"+origin.sha {
				http.NotFound(w, r)
				return
			}
			origin.codeload.Add(1)
			w.Header().Set("Content-Type", "application/x-gzip")
			_, _ = w.Write(archive)
		case "raw.githubusercontent.com":
			if r.Method != http.MethodGet || r.URL.Path != origin.repository()+"/"+origin.sha+"/package.json" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(manifestBody)
		default:
			http.NotFound(w, r)
		}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	origin.registry = &npmTestRegistry{URL: "https://localhost:" + server.URL[strings.LastIndex(server.URL, ":")+1:]}
	origin.registry.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	origin.registry.CAPath = filepath.Join(t.TempDir(), "origin-ca.pem")
	if err := os.WriteFile(origin.registry.CAPath, []byte(origin.registry.CAPEM), 0600); err != nil {
		t.Fatal(err)
	}
	origin.tarballURL = "https://codeload.github.com" + origin.repository() + "/tar.gz/" + origin.sha
	origin.ref = "github:" + origin.owner + "/" + origin.repo + "#" + origin.sha
	origin.address = server.Listener.Addr().String()
	return origin
}

// TestYarnGitHubArchiveDependencies covers github: dependencies on both
// generations. Yarn 4 lists the repository's refs with git and then downloads
// the commit archive from github.com, which redirects to codeload; Yarn
// Classic reads the refs and the manifest over HTTP and downloads the codeload
// tarball directly. The codeload response is evaluated with its URL as the
// source.
func TestYarnGitHubArchiveDependencies(t *testing.T) {
	for _, generation := range yarnGenerations {
		for _, test := range []struct {
			name   string
			failed bool
		}{{"allow", false}, {"block", true}} {
			t.Run(generation.name+"/"+test.name, func(t *testing.T) {
				executable := yarnTestExecutable(t, generation.variable)
				origin := startYarnGitHubOrigin(t, "npm/git-package/package.json")
				var tunnels atomic.Int32
				upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:proxy-secret", hits: &tunnels, connectAddress: origin.address})
				tunnel := strings.Replace(upstream.URL, "://", "://proxy:proxy-secret@", 1)
				var dir, rc string
				if generation.name == "classic" {
					rc = classicYarnrc(origin.registry, `https-proxy "`+tunnel+`"`+"\n")
					dir = newYarnTestProject(t, ".yarnrc", rc)
				} else {
					// Yarn 4.10 and later only fetch approved repositories.
					rc = berryYarnrc(origin.registry, "nodeLinker: node-modules\napprovedGitRepositories:\n  - \"**\"\n")
					dir = newBerryTestProject(t, rc)
					// Yarn 4 ignores the standard proxy variables, so the
					// chain is configured the way its own settings read it.
					t.Setenv("YARN_HTTPS_PROXY", tunnel)
				}
				// The chain remaps the GitHub hosts onto the origin, so SCFW
				// must trust its certificate upstream.
				t.Setenv("NODE_EXTRA_CA_CERTS", origin.registry.CAPath)
				before := readYarnProjectFiles(t, dir)
				outcome := evaluation.OutcomeAllow
				if test.failed {
					outcome = evaluation.OutcomeBlock
				}
				// Yarn 4 resolves the pinned commit with `git ls-remote`, which
				// SCFW's Git client forwards with the user's Git settings, so the
				// chain and the origin's CA are configured as Git settings.
				t.Setenv("GIT_CONFIG_COUNT", "2")
				t.Setenv("GIT_CONFIG_KEY_0", "http.proxy")
				t.Setenv("GIT_CONFIG_VALUE_0", tunnel)
				t.Setenv("GIT_CONFIG_KEY_1", "http.sslCAInfo")
				t.Setenv("GIT_CONFIG_VALUE_1", origin.registry.CAPath)
				run := runYarnThroughProxy(t, executable, yarnAddDependency(generation.name, origin.ref), outcome)
				if test.failed {
					assertYarnFailed(t, run)
				} else {
					assertYarnSucceeded(t, run)
				}
				if tunnels.Load() == 0 {
					t.Fatal("the GitHub hosts were not reached through the chained proxy")
				}
				if downloads := origin.codeload.Load(); downloads != yarnArchiveDownloads(generation.name, test.failed) {
					t.Fatalf("codeload downloads = %d, want %d", downloads, yarnArchiveDownloads(generation.name, test.failed))
				}
				if !test.failed {
					wantPacks := int32(0)
					if generation.name == "berry" {
						// Yarn 4 reads the manifest through one resolution clone.
						wantPacks = 1
					}
					if origin.packs.Load() != wantPacks {
						t.Fatalf("git pack downloads = %d, want %d", origin.packs.Load(), wantPacks)
					}
				}
				assertYarnArchiveRun(t, run, dir, generation.rcName, rc, "lab-git-pkg", before, []string{origin.tarballURL}, test.failed)
			})
		}
	}
}
