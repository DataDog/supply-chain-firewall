// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
)

// seedPnpmURLLockfile installs the direct tarball URL dependency once, then
// leaves only the manifest and lockfile, with an empty store, so the next
// command downloads the lockfile's resolution.tarball URL again.
func seedPnpmURLLockfile(t *testing.T, executable string, registry *npmTestRegistry, dir string) {
	t.Helper()
	assertPnpmSucceeded(t, runPnpmThroughProxy(t, executable, []string{"add", registry.URL + npmDirectTarballPath}, evaluation.OutcomeAllow))
	if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
		t.Fatal(err)
	}
	usePnpmStore(t, t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

// pnpmURLDependencyDownloads is the tarball downloads pnpm makes when it
// resolves a URL dependency: a HEAD and a GET, which pnpm 12 repeats because
// it downloads the tarball once to read its manifest and once to unpack it.
func pnpmURLDependencyDownloads(major int) int32 {
	if major == 12 {
		return 4
	}
	return 2
}

// pnpmFirstURLDownload is the downloads that reach the origin when the first
// one is blocked: pnpm never retries a refused tarball fetch.
func pnpmFirstURLDownload(int) int32 { return 2 }

// pnpmLockfileDownload is the download a lockfile install makes: the manifest
// comes from the lockfile, so only the tarball is fetched.
func pnpmLockfileDownload(int) int32 { return 1 }

// TestPnpmArchiveDependencies covers the tarball-shaped downloads pnpm makes
// outside the registry layout: a direct tarball URL dependency, a
// codeload-shaped git archive URL, the target of a redirected archive URL, and
// a lockfile resolution.tarball URL. pnpm HEADs a URL dependency before it
// downloads it; only the download is evaluated, with its URL as the source.
func TestPnpmArchiveDependencies(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		for _, test := range []struct {
			name    string
			args    func(registry *npmTestRegistry) []string
			seed    func(t *testing.T, registry *npmTestRegistry, dir string)
			outcome evaluation.Outcome
			// hits is the number of tarball downloads the run itself may make.
			hits   func(major int) int32
			failed bool
			// source is the URL path the package must be reported from.
			source string
		}{
			{name: "url-allow", args: func(registry *npmTestRegistry) []string {
				return []string{"add", registry.URL + npmDirectTarballPath}
			}, outcome: evaluation.OutcomeAllow, hits: pnpmURLDependencyDownloads, source: npmDirectTarballPath},
			{name: "url-block", args: func(registry *npmTestRegistry) []string {
				return []string{"add", registry.URL + npmDirectTarballPath}
			}, outcome: evaluation.OutcomeBlock, hits: pnpmFirstURLDownload, source: npmDirectTarballPath, failed: true},
			{name: "git-archive-allow", args: func(registry *npmTestRegistry) []string {
				return []string{"add", registry.URL + npmGitArchivePath}
			}, outcome: evaluation.OutcomeAllow, hits: pnpmURLDependencyDownloads, source: npmGitArchivePath},
			{name: "git-archive-block", args: func(registry *npmTestRegistry) []string {
				return []string{"add", registry.URL + npmGitArchivePath}
			}, outcome: evaluation.OutcomeBlock, hits: pnpmFirstURLDownload, source: npmGitArchivePath, failed: true},
			{name: "redirected-archive-allow", args: func(registry *npmTestRegistry) []string {
				return []string{"add", registry.URL + npmRedirectingArchivePath}
			}, outcome: evaluation.OutcomeAllow, hits: pnpmURLDependencyDownloads, source: npmRedirectTargetPath},
			{name: "redirected-archive-block", args: func(registry *npmTestRegistry) []string {
				return []string{"add", registry.URL + npmRedirectingArchivePath}
			}, outcome: evaluation.OutcomeBlock, hits: pnpmFirstURLDownload, source: npmRedirectTargetPath, failed: true},
			{name: "lockfile-install-allow", args: func(*npmTestRegistry) []string {
				return []string{"install"}
			}, seed: func(t *testing.T, registry *npmTestRegistry, dir string) {
				seedPnpmURLLockfile(t, executable, registry, dir)
			}, outcome: evaluation.OutcomeAllow, hits: pnpmLockfileDownload, source: npmDirectTarballPath},
			{name: "lockfile-frozen-block", args: func(*npmTestRegistry) []string {
				return []string{"install", "--frozen-lockfile"}
			}, seed: func(t *testing.T, registry *npmTestRegistry, dir string) {
				seedPnpmURLLockfile(t, executable, registry, dir)
			}, outcome: evaluation.OutcomeBlock, hits: pnpmLockfileDownload, source: npmDirectTarballPath, failed: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				registry := startNpmRegistry(t)
				dir := newPnpmTestProject(t, registry, "")
				if test.seed != nil {
					test.seed(t, registry, dir)
				}
				manifest, err := os.ReadFile(filepath.Join(dir, "package.json"))
				if err != nil {
					t.Fatal(err)
				}
				lockfile, lockErr := os.ReadFile(filepath.Join(dir, "pnpm-lock.yaml"))
				npmrc, err := os.ReadFile(filepath.Join(dir, ".npmrc"))
				if err != nil {
					t.Fatal(err)
				}
				before := registry.TarballHits.Load()
				run := runPnpmThroughProxy(t, executable, test.args(registry), test.outcome)
				if test.failed {
					assertPnpmFailed(t, run)
				} else {
					assertPnpmSucceeded(t, run)
				}
				if hits := registry.TarballHits.Load() - before; hits != test.hits(major) {
					t.Fatalf("tarball downloads = %d, want %d", hits, test.hits(major))
				}
				if run.calls != 1 || !slices.Equal(run.sources, []string{registry.URL + test.source}) {
					t.Fatalf("evaluations = %d from %v, want 1 of %s", run.calls, run.sources, registry.URL+test.source)
				}
				if test.failed {
					after, err := os.ReadFile(filepath.Join(dir, "package.json"))
					if err != nil || !bytes.Equal(after, manifest) {
						t.Fatalf("a failed command changed package.json: %q (error %v)", after, err)
					}
					afterLock, afterLockErr := os.ReadFile(filepath.Join(dir, "pnpm-lock.yaml"))
					if (afterLockErr == nil) != (lockErr == nil) || !bytes.Equal(afterLock, lockfile) {
						t.Fatalf("a failed command changed pnpm-lock.yaml: %q (error %v)", afterLock, afterLockErr)
					}
					if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg")); err == nil {
						t.Fatal("blocked package was installed")
					}
				} else if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg", "package.json")); err != nil {
					t.Fatalf("package not installed: %v", err)
				}
				if after, err := os.ReadFile(filepath.Join(dir, ".npmrc")); err != nil || !bytes.Equal(after, npmrc) {
					t.Fatalf(".npmrc changed: %q (error %v)", after, err)
				}
				assertProxyCleaned(t, run.config)
			})
		}
	})
}

// startPnpmUnknownHost serves a registry-layout tarball from an origin no pnpm
// setting names: a second server, whose certificate joins the .npmrc CA bundle
// so pnpm can reach it. An IP-literal origin cannot play the unknown host,
// because pnpm checks a proxied IP literal's certificate against localhost.
func startPnpmUnknownHost(t *testing.T, tarball []byte) *npmTestRegistry {
	t.Helper()
	digest := sha512.Sum512(tarball)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(digest[:])
	packument := readProxyFixture(t, "npm/packument.json.tmpl")
	var registry *npmTestRegistry
	registry = startYarnArchiveServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lab-pkg":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, packument, registry.URL+"/lab-pkg/-/lab-pkg-1.0.0.tgz", integrity)
		case "/lab-pkg/-/lab-pkg-1.0.0.tgz":
			registry.TarballHits.Add(1)
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(tarball)
		default:
			http.NotFound(w, r)
		}
	})
	return registry
}

// TestPnpmUnknownHostTarballIdentity covers a registry-layout tarball URL on a
// host no pnpm setting names. SCFW evaluates the package the URL identifies and
// refuses the download before forwarding it, so a blocked package never
// reaches pnpm, and a tarball whose package.json declares another package is
// withheld even when the policy allows it.
func TestPnpmUnknownHostTarballIdentity(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		for _, test := range []struct {
			name string
			// tarball is the package the download declares.
			tarball func(t *testing.T) []byte
			outcome evaluation.Outcome
			// hits is the tarball requests that reach the unknown host: a
			// HEAD always does, a blocked GET is refused before it is forwarded.
			hits   func(major int) int32
			failed bool
		}{
			{name: "allow", tarball: npmTarball, outcome: evaluation.OutcomeAllow, hits: pnpmURLDependencyDownloads},
			{name: "block", tarball: npmTarball, outcome: evaluation.OutcomeBlock, hits: func(int) int32 { return 1 }, failed: true},
			{name: "identity-mismatch", tarball: func(t *testing.T) []byte {
				return npmTarballFrom(t, "pnpm/other-package")
			}, outcome: evaluation.OutcomeAllow, hits: pnpmFirstURLDownload, failed: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				registry := startNpmRegistry(t)
				unknown := startPnpmUnknownHost(t, test.tarball(t))
				// pnpm must reach the unknown host, so its certificate joins
				// the .npmrc CA bundle.
				if err := os.WriteFile(registry.CAPath, append([]byte(registry.CAPEM), []byte(unknown.CAPEM)...), 0600); err != nil {
					t.Fatal(err)
				}
				dir := newPnpmTestProject(t, registry, "")
				url := unknown.URL + "/lab-pkg/-/lab-pkg-1.0.0.tgz"
				before := unknown.TarballHits.Load()
				run := runPnpmThroughProxy(t, executable, []string{"add", url}, test.outcome)
				if test.failed {
					assertPnpmFailed(t, run)
				} else {
					assertPnpmSucceeded(t, run)
				}
				if hits := unknown.TarballHits.Load() - before; hits != test.hits(major) {
					t.Fatalf("tarball requests = %d, want %d", hits, test.hits(major))
				}
				if run.calls != 1 || !slices.Equal(run.sources, []string{url}) {
					t.Fatalf("evaluations = %d from %v, want 1 of %s", run.calls, run.sources, url)
				}
				if _, err := os.Stat(filepath.Join(dir, "node_modules", "lab-pkg", "package.json")); (err == nil) != !test.failed {
					t.Fatalf("package installed = %v, want %v", err == nil, !test.failed)
				}
				assertProxyCleaned(t, run.config)
			})
		}
	})
}

// TestPnpmGitHubArchiveDependencies covers a github: dependency, which pnpm 10
// and 11 resolve with git through the proxy and then download as a GitHub
// codeload tarball, whose response is evaluated with its URL as the source.
func TestPnpmGitHubArchiveDependencies(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		if major == 12 {
			t.Skip("pnpm 12 clones GitHub dependencies with Git; see TestPnpm12GitHubDependencyClone")
		}
		for _, test := range []struct {
			name   string
			failed bool
		}{{"allow", false}, {"block", true}} {
			t.Run(test.name, func(t *testing.T) {
				origin := startYarnGitHubOrigin(t, "pnpm/git-package/package.json")
				var tunnels atomic.Int32
				upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:proxy-secret", hits: &tunnels, connectAddress: origin.address})
				tunnel := strings.Replace(upstream.URL, "://", "://proxy:proxy-secret@", 1)
				newPnpmTestProject(t, origin.registry, "https-proxy="+tunnel+"\n")
				t.Setenv("NODE_EXTRA_CA_CERTS", origin.registry.CAPath)
				outcome := evaluation.OutcomeAllow
				if test.failed {
					outcome = evaluation.OutcomeBlock
				}
				run := runPnpmThroughProxy(t, executable, []string{"add", origin.ref}, outcome)
				if test.failed {
					assertPnpmFailed(t, run)
				} else {
					assertPnpmSucceeded(t, run)
				}
				if tunnels.Load() == 0 {
					t.Fatal("the GitHub hosts were not reached through the chained proxy")
				}
				if downloads := origin.codeload.Load(); downloads != 1 {
					t.Fatalf("codeload downloads = %d, want 1", downloads)
				}
				if run.calls != 1 || !slices.Equal(run.sources, []string{origin.tarballURL}) {
					t.Fatalf("evaluations = %d from %v, want 1 of %s", run.calls, run.sources, origin.tarballURL)
				}
				if _, err := os.Stat(filepath.Join("node_modules", "lab-git-pkg", "package.json")); (err == nil) != !test.failed {
					t.Fatalf("package installed = %v, want %v", err == nil, !test.failed)
				}
				assertProxyCleaned(t, run.config)
			})
		}
	})
}

// pnpm 12 resolves a github: dependency by cloning it with Git, whose traffic
// crosses SCFW's proxy as opaque tunnels, and no checkout it leaves behind is
// identified. This documents that limitation.
func TestPnpm12GitHubDependencyClone(t *testing.T) {
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		if major != 12 {
			t.Skip("pnpm 10 and 11 download the codeload tarball; see TestPnpmGitHubArchiveDependencies")
		}
		origin := startYarnGitHubOrigin(t, "pnpm/git-package/package.json")
		var tunnels atomic.Int32
		upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:proxy-secret", hits: &tunnels, connectAddress: origin.address})
		tunnel := strings.Replace(upstream.URL, "://", "://proxy:proxy-secret@", 1)
		newPnpmTestProject(t, origin.registry, "https-proxy="+tunnel+"\n")
		t.Setenv("NODE_EXTRA_CA_CERTS", origin.registry.CAPath)
		run := runPnpmThroughProxy(t, executable, []string{"add", origin.ref}, evaluation.OutcomeBlock)
		assertPnpmSucceeded(t, run)
		if tunnels.Load() == 0 || origin.packs.Load() == 0 {
			t.Fatalf("tunnels=%d packs=%d, want the repository cloned with Git through the chained proxy", tunnels.Load(), origin.packs.Load())
		}
		if downloads := origin.codeload.Load(); downloads != 0 {
			t.Fatalf("codeload downloads = %d, want none", downloads)
		}
		if run.calls != 0 {
			t.Fatalf("evaluations = %d from %v, want the clone to be unseen", run.calls, run.sources)
		}
		if _, err := os.Stat(filepath.Join("node_modules", "lab-git-pkg", "package.json")); err != nil {
			t.Fatalf("the cloned dependency was not installed: %v", err)
		}
		assertProxyCleaned(t, run.config)
	})
}

// pnpmForcedArchiveDownloads is the tarball downloads the allow subcases of
// TestPnpmForcedPartialAndCachedArchives expect: pnpm discards the forced 206
// or 304 and asks again, and SCFW re-fetches one complete copy in between.
// pnpm 12 asks a second time after a bodyless 304.
func pnpmForcedArchiveDownloads(major, status int) int32 {
	if major == 12 && status == http.StatusNotModified {
		return 4
	}
	return 3
}

// TestPnpmForcedPartialAndCachedArchives covers responses pnpm itself never
// asks for, forced by the origin: a tarball GET answered 206 with the complete
// body, or 304, while later requests get full responses. pnpm discards a
// forced 206 or 304 and asks again, so each subcase pins the exact number of
// downloads: the allow subcases count one request more than pnpm's own, the
// complete copy SCFW re-fetches and evaluates before releasing the forced
// response, and the block subcases prove the blocked package is not installed
// (their second request is SCFW's re-fetch or pnpm's own retry).
func TestPnpmForcedPartialAndCachedArchives(t *testing.T) {
	tarball := npmTarball(t)
	forEachPnpm(t, func(t *testing.T, major int, executable string) {
		for _, status := range []struct {
			name string
			code int
		}{{"partial", http.StatusPartialContent}, {"cached", http.StatusNotModified}} {
			for _, test := range []struct {
				name   string
				failed bool
			}{{"allow", false}, {"block", true}} {
				t.Run(status.name+"-"+test.name, func(t *testing.T) {
					var requests atomic.Int32
					var conditionalMutex sync.Mutex
					var conditional []string
					registry := startYarnArchiveServer(t, func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != npmDirectTarballPath {
							http.NotFound(w, r)
							return
						}
						if r.Method == http.MethodHead {
							w.WriteHeader(http.StatusOK)
							return
						}
						conditionalMutex.Lock()
						for _, name := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
							if r.Header.Get(name) != "" {
								conditional = append(conditional, name)
							}
						}
						conditionalMutex.Unlock()
						if requests.Add(1) == 1 {
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
					newPnpmTestProject(t, registry, "fetch-retry-mintimeout=100\nfetch-retry-maxtimeout=200\n")
					// pnpm 10 reads npm_config_* and pnpm 11 and 12 read
					// pnpm_config_*; keep the retry pnpm makes after a forced
					// 206 or 304 fast.
					t.Setenv("npm_config_fetch_retry_mintimeout", "100")
					t.Setenv("pnpm_config_fetch_retry_mintimeout", "100")
					t.Setenv("npm_config_fetch_retry_maxtimeout", "200")
					t.Setenv("pnpm_config_fetch_retry_maxtimeout", "200")
					outcome := evaluation.OutcomeAllow
					if test.failed {
						outcome = evaluation.OutcomeBlock
					}
					run := runPnpmThroughProxy(t, executable, []string{"add", registry.URL + npmDirectTarballPath}, outcome)
					if test.failed {
						assertPnpmFailed(t, run)
					} else {
						assertPnpmSucceeded(t, run)
					}
					conditionalMutex.Lock()
					sent := slices.Clone(conditional)
					conditionalMutex.Unlock()
					if len(sent) != 0 {
						t.Fatalf("pnpm sent conditional headers %v; a forced response is no longer what exercises the hook", sent)
					}
					// pnpm asks again after its download is answered with the
					// forced status; without SCFW's re-fetch the allow subcases
					// would count pnpm's requests alone, so the exact numbers
					// prove the complete copy was fetched and evaluated before
					// the forced response was released. A blocked package stops
					// pnpm at the refusal, whatever made the second request.
					wantRequests := int32(2)
					if !test.failed {
						wantRequests = pnpmForcedArchiveDownloads(major, status.code)
					}
					if served := requests.Load(); served != wantRequests {
						t.Fatalf("requests = %d, want %d: pnpm's discarded download and retries, plus the evaluated full re-fetch", served, wantRequests)
					}
					if run.calls != 1 || !slices.Equal(run.sources, []string{registry.URL + npmDirectTarballPath}) {
						t.Fatalf("evaluations = %d from %v, want 1 of %s", run.calls, run.sources, registry.URL+npmDirectTarballPath)
					}
					if _, err := os.Stat(filepath.Join("node_modules", "lab-pkg", "package.json")); (err == nil) != !test.failed {
						t.Fatalf("package installed = %v, want %v", err == nil, !test.failed)
					}
					assertProxyCleaned(t, run.config)
				})
			}
		}
	})
}
