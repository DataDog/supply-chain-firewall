# Public npm baseline

Run suite `npm-baseline` with a native npm cell in the shared matrix. The cell must set
`manager` to `npm`, `modes` to `["resolution", "proxy"]`, `suites` to `["npm-baseline"]`,
and absolute `executable` (npm), `runtime` (Node), and `git` paths with exact
versions. Provision npm separately from the fresh projects under test. The pilot
uses npm7.0.0 with Node14.21.3 and npm10.9.9 with Node22.23.3; other native supported
cells use the same recipes. The examples in the package README describe the
remaining matrix fields and GoReleaser artifact requirements.

From the repository root, after the required lint/build and offline checks:

```sh
export SCFW_E2E_BINARY=/absolute/path/to/preserved-goreleaser-artifact/scfw
export SCFW_E2E_MATRIX=/absolute/path/to/npm-matrix.json
export SCFW_E2E_CELL=linux-arm64-npm7-node14
export SCFW_E2E_SUITES=npm-baseline
export SCFW_E2E_OUTPUT=/absolute/path/outside/checkouts/npm-run-001
export SCFW_E2E_DISCOVERY="$SCFW_E2E_OUTPUT/discovery.json"
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```

Copy the GoReleaser artifact outside `dist` before execution so another build cannot
remove it during a run. Keep its checksum with the evidence. Use a fresh output
path per attempt and repeat for the other pinned cell. Never
reuse results as a successful rerun or replace a failing package after execution.

Discovery reads full public npm packuments for candidate names in
`../npm_candidates.json`. It chooses an exact stable version published more than
48h ago, records `time[version]`, the tarball URL and SHA512 integrity, and retains
all fetched metadata. Candidate releases must have no runtime dependencies,
installation lifecycle scripts, or deprecation. Unknown Node engine ranges are
ineligible; this pool uses only simple lower bounds. Each case independently
revalidates its exact artifact and publication time. Scoped type packages are
verified through installed metadata; ordinary modules are also imported by the
pinned real Node executable.

The suite registers72 cases, covering:

| Source | Variants |
| --- | --- |
| CORE-01 | ALLOW in resolution and proxy modes |
| CORE-02 | BLOCK with and without `--error-on-block`, both modes |
| CORE-10 | Proxy flag unset, `0`, `true`, and `1` |
| CORE-12 | Explicit real npm executable through a symlink in a path with spaces, both modes |
| NPM-01 | ALLOW/BLOCK for all12 declared install aliases and a scoped package, both modes |
| REPORT-01 | Local ALLOW/BLOCK identity, command, executable and Git metadata, both modes |
| LIFE-01 | Successful and blocked resolution temporary-project/proxy listener and CA cleanup |

All cases launch the real SCFW artifact. npm caches, configuration files, projects,
HOME and SCFW_HOME are isolated. Installs retain the public registry and disable
npm audit/funding/update requests and lifecycle scripts; those behaviors belong
to other suites. Real default local verifier services remain enabled.

Reports are checked separately from installed package metadata and lockfile
artifact URL/integrity. Resolution BLOCK preserves the original manifest and
lockfile byte-for-byte. Proxy BLOCK requires a nonzero npm exit, an exact policy
finding and target absence; it makes no rollback claim. Only proxy flag `1`
enables interception. Every case checks temporary-material cleanup, and proxy
cases also verify that observed listeners close. npm `ci`, dependency graphs,
recent releases and additional project behavior are outside this baseline suite.

`isntall` requires the explicit `npm-alias-isntall-install` capability. Native
npm7.0.0 lacks that install alias: abbreviation selects `isntall-clean` (`ci`), so
the four install-alias variants are declared N/A for that exact pin. Native
npm10.9.9 installs the requested package and must declare the capability. Do not
infer this behavior for every7.x release or suppress other aliases. Verify each
new pin directly in an isolated project with an empty lockfile using
`npm isntall <discovered-name>@<version>`; retain argv, exit and installed state
before deciding the capability. Record that evidence in the cell's provisioning
notes. The registry installs and SCFW assertions remain mandatory when the alias
is applicable.

Each exact-version matrix cell must carry this verified native capability.
The npm project suite's npm7.0.0 boundary coverage should also characterize `isntall` as `ci`,
including the mode-specific protection of locked dependencies. This is native
manager behavior, not a SCFW protection exemption.
