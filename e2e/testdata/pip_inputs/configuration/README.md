# pip configuration and lifecycle boundaries

`pip-config-lifecycle` registers 44 cases. Both modes cover command/global configuration,
environment/flag precedence, `--python` and `PIP_PYTHON`, a real shell launcher,
value-taking global options and unambiguous abbreviations. Each install form has
ALLOW/BLOCK variants. Additional cases cover dry-run, native resolution failure,
an allowed install that later fails on the filesystem, an existing venv's blocked
upgrade, a successful upgrade, and the pip resolution version boundary.

All distributions come from public PyPI. Ordinary cases use the parent runner's
old-wheel discovery; upgrades use its native two-version required graph. Exact
artifacts, installed metadata/imports, policy records and cleanup remain checked.
The virtual-environment cases bootstrap the pinned real pip and an older public
package version, then run the asserted upgrade through SCFW. A blocked upgrade
must preserve every installed distribution file and an existing project file.

Configuration templates intentionally put unusable public PyPI paths in lower
precedence settings. Selected command/environment/CLI settings point to the real
Simple index. Original configuration bytes must survive. Interpreter cases use a
real isolated venv with spaces in its path and its own pip.conf; installation must
land there. The shell template delegates every argument to the pinned real pip,
and native debug output proves the interpreter. No fake manager is used.

The global option values include a filename named `help` so it cannot be mistaken
for a command. `--log-f` and `--time` exercise native unambiguous abbreviations.
No new promise is made for pip's legacy `--isolated` discovery behavior.

The explicit public wheel URL in dry-run forces an artifact request: resolution
skips dry-run evaluation and installs nothing; proxy blocks the exact required
wheel and also installs nothing. Unavailable-version and filesystem-failure cases
compare the direct pinned manager's exit and diagnostic with SCFW; policy BLOCK
cannot substitute for native failure. The latter must have an ALLOW record before
the native installer fails, preserving the conflicting target file.

Version/capability inventory:

- `pip-resolution-report`: pip >=22.2 cells; ordinary cases depend on its report
  support. Verified pins:22.2,22.3,26.2.
- `pip-python-option`: native `pip --help` advertises `--python`; verified absent
  in22.2 and present in22.3/26.2. Only the eight interpreter-selection cases need it.
- `pip-below-resolution-minimum`: dedicated22.1.2 cell. Four cases require
  resolution install rejection, native informational success, and proxy
  ALLOW/BLOCK. There is no invented proxy minimum guard.

With both modes enabled:22.2 has32 applicable cases and12 declared N/A;
22.3/26.2 each have40 applicable and4 N/A;22.1.2 has4 applicable and40 N/A.
Capabilities must be verified when provisioning another exact pin. Missing tools,
network or workers are failures, never capability N/A. Native macOS/amd64 live
execution is left to the full matrix; current implementation evidence is Linux
arm64 with Python3.11.18.

Fixtures: `pip.conf.tmpl` provides the two configuration sections;
`pip-shim.sh.tmpl` launches the actual pinned pip; `snapshot_distributions.py`
reads installed distribution metadata and hashes all recorded files without
extracting or executing archive content.

```sh
export SCFW_E2E_BINARY=/absolute/path/to/goreleaser/scfw
export SCFW_E2E_MATRIX=/absolute/path/to/verified-matrix.json
export SCFW_E2E_CELL=your-exact-pip-cell
export SCFW_E2E_SUITES=pip-config-lifecycle
export SCFW_E2E_OUTPUT=/absolute/path/outside/source/new-run
export SCFW_E2E_DISCOVERY=$SCFW_E2E_OUTPUT/discovery.json
go test -tags=e2e ./e2e -run '^Test(Plan|Discover|E2E)$' -count=1 -timeout=25m
```
