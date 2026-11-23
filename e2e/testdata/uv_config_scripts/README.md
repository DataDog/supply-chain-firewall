# uv configuration discovery and proxied scripts

Run the real GoReleaser SCFW artifact and pinned uv with Python 3.12.10.
Adapt `matrix.json` to the provisioned native Linux/macOS amd64/arm64 cell:

```sh
export SCFW_E2E_BINARY=/absolute/path/to/scfw
export SCFW_E2E_MATRIX=/absolute/path/to/matrix.json
export SCFW_E2E_CELL=linux-arm64-uv-0.13.4-python-3.12.10
export SCFW_E2E_SUITES=uv-config-scripts
export SCFW_E2E_DISCOVERY=/absolute/evidence/uv-config-scripts/discovery.json
export SCFW_E2E_OUTPUT=/absolute/evidence/uv-config-scripts/run
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```

Keep the discovery manifest for subsequent cells and attempts; only discovery
writes it. Each execution needs a new output directory. Missing tools or network,
expired discoveries, and assertion failures remain failures.

## Variant inventory

- UV-06: `local-script` and `symlink-script`, each ALLOW/BLOCK; local PEP 723
  metadata contains public index/trust settings and the discovered exact public
  wheel URL. The download triggers policy; locking does not execute the body.
- UV-06: `registry-metadata-only` uses an exact blocked registry requirement.
  PyPI advertises separate metadata, so a successful lock with no distribution
  policy is explicitly recorded as `METADATA_ONLY`, not policy ALLOW.
- UV-06: inline HTTP/HTTPS proxies, inline proxy with `--no-config` or explicit
  config, remote/stdin scripts, oversized scripts and malformed metadata reject
  before proxy setup. A seekable stdin descriptor proves zero bytes consumed.
  The sole controlled origin serves the rejected remote script and records zero
  requests; all package artifacts still come from real public PyPI.
- UV-07: uv.toml, pyproject, project over user config, uv.toml over pyproject,
  CLI/environment explicit config, environment index over file, CLI index over
  environment, CLI/environment no-config, relative directory, physical symlink
  parent, canonical/legacy working-directory environment, recursive workspace membership and
  workspace exclusions, each ALLOW/BLOCK.
- UV-07: merged project, explicit, symlink and workspace configs, each ALLOW/BLOCK.
  File proxy points at an unavailable loopback endpoint but explicitly bypasses
  public PyPI hosts. Native uv could bypass inspection unless SCFW supplies its
  invocation config. Exact BLOCK therefore verifies the interception path.
  `observe.py` captures the actual temporary config while SCFW runs; tests check
  its invocation proxy, deletion, closed listeners, and original source bytes.
  Forwarding-proxy routing probes are outside this suite.

All 53 variants are registered. Eight merged-config variants require the declared
`uv-file-proxy` capability: verified present on uv 0.13.4 and absent on 0.9.0
(native uv rejects `https-proxy` as unknown). This does not claim an intermediate
version boundary. Four working-directory environment variants require `uv-working-directory-env`:
native forced reinstalls verify that both `UV_WORKING_DIR` and its legacy alias
`UV_WORKING_DIRECTORY` are honored on 0.13.4 and ignored on 0.9.0. Explicit
`--directory` works on both. The remaining 41 variants apply to both pins.

The Python observer launches the unchanged SCFW executable with the real manager;
it does not replace uv or inject production hooks. It preserves SCFW stdout,
stderr and exit status, records the full invocation, snapshots temporary config,
and reports the shared stdin descriptor position. Original configuration/script
bytes and before/after digests, local policy identity, exact package/lock state,
and temporary-material/listener cleanup are asserted.

Native macOS validation must run on a provisioned macOS worker. Linux success is
not evidence that the macOS matrix cells passed.
