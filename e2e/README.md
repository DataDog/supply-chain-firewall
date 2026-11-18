# Real-command E2E tests

This opt-in external test package executes an unchanged GoReleaser SCFW artifact and real package managers against public registries. Ordinary untagged `go test ./...` excludes it. The example below runs the pip baseline suite; other suites select their own manager and fixtures.

Provide a native Linux/macOS worker, a supported pinned pip with both `pip` and `pip3` launchers, its matching Python with `venv`, and Git. No credentials are required. Build and check the artifact:

```sh
make lint
make golangci-lint
goreleaser build --snapshot --clean
go test -tags=e2e ./e2e -run '^TestHarness' -count=1
go vet -tags=e2e ./e2e
```

Copy `testdata/matrix.json` outside the checkout, replace absolute executable paths, and set exact installed versions and native OS/architecture. Missing tools or mismatched versions fail. This example declares a pilot, not the final supported matrix.

```sh
export SCFW_E2E_BINARY=/absolute/path/to/dist/scfw_linux_arm64_v8.0/scfw
export SCFW_E2E_MATRIX=/absolute/path/to/matrix.json
export SCFW_E2E_CELL=linux-arm64-pip-26.2.2-python-3.12.10
export SCFW_E2E_SUITES=pip-baseline
export SCFW_E2E_OUTPUT=/absolute/path/outside/checkouts/run-001
export SCFW_E2E_DISCOVERY="$SCFW_E2E_OUTPUT/discovery.json"
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```

Use a fresh output directory for every attempt. Discovery retains bounded public PyPI JSON, chooses an exact non-yanked pure Python wheel older than48h, and records its upload time, URL and SHA256. Each case revalidates the exact file before execution. The candidate pool contains benign leaf packages and accepts simple Python3 minimum-version constraints; unsupported constraints are ineligible. No recent-package behavior is claimed by this pilot.

Each case uses a fresh HOME, SCFW_HOME, cache, temporary directory, working directory and Python virtual environment. The pinned real pip installs into a separate target directory; the clean virtual environment verifies installed metadata and imports without access to ambient packages. No manager shims or registry fixtures are substituted. Default public verifier services remain enabled. Public-origin request counts are not observable and are not asserted.

`planned.json` and `results.json` contain schema version1 and matching `cell/suite/scenario/variant` identities. Missing or duplicate results and any applicable non-PASS status fail reconciliation. Capability-based N/A retains its declared reason. Cases retain argv, allowlisted environment, stdout/stderr hashes, local policy JSONL, pip artifact report, installation observations and cleanup evidence. Preflight retains tool version output, SCFW version, native OS version and the release artifact SHA256. Package verifier failures remain visible in policy evidence and preserve SCFW's existing best-effort semantics.

The pip baseline suite registers 20 cases: CORE-01 ALLOW and CORE-02 exact-list BLOCK (both exit-flag variants) in resolution/proxy modes; CORE-10 unset/0/true/1 proxy selection; CORE-12 pip3 and explicit executables in paths with spaces; REPORT-01 local ALLOW/BLOCK identity and Git metadata; LIFE-01 allowed/blocked proxy cleanup followed by a fresh allowed invocation. Reports are policy observations; installation is independently verified. Cleanup checks retained temporary material and observed loopback listener closure.

New manager suites register `scenario` callbacks in their own files, plus discovery/revalidation functions keyed by `DiscoveryKey`. An empty discovery key supports direct informational commands. `caseRun` exposes isolated paths/environment, the pinned cell, command execution and evidence retention; it does not embed manager dependency resolution. Add scenario variants to their owning suite, retaining the scenario IDs in `testdata/scenario_ids.json`.
