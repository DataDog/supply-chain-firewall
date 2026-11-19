# uv/uvx baseline suite

Run with the shared E2E runner instructions in `../../../README.md`, selecting
`SCFW_E2E_SUITES=uv-baseline` and the supplied matrix example after replacing executable
paths and native platform. Provide pinned uv 0.13.4 and its matching sibling uvx,
Python 3.12.10, Git, and an unchanged native GoReleaser SCFW artifact.

```sh
export SCFW_E2E_BINARY=/absolute/path/to/scfw
export SCFW_E2E_MATRIX=/absolute/path/to/uv-matrix.json
export SCFW_E2E_CELL=linux-arm64-uv-0.13.4-python-3.12.10
export SCFW_E2E_SUITES=uv-baseline
export SCFW_E2E_OUTPUT=/absolute/path/outside/checkouts/uv-run-001
export SCFW_E2E_DISCOVERY="$SCFW_E2E_OUTPUT/discovery.json"
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```

Discovery uses live PyPI and retains exact metadata and artifact identities.
The tool candidate pool contains benign dependency-free CLI packages. It chooses
two numeric stable releases with compatible universal wheels older than 48h.
The schema's additive `candidate.related.bootstrap` contains the complete older
candidate for the upgrade case; both candidates are validated and revalidated.
A bounded requirement with `--resolution lowest-direct` primes the old version;
the asserted upgrade then requests the exact discovered new version. A permanently
exact old installation constraint would make native uv reject the upgrade itself.

Thirty cases cover these assigned variants:

| Source | Variants |
| --- | --- |
| CORE-01 / UV-01 | Real `uv pip install` ALLOW baseline |
| CORE-02 | Exact-list BLOCK with and without `--error-on-block` |
| CORE-10 | Unset/0/true reject package operations; only1 enables proxy |
| CORE-12 | uv and uvx explicit executable paths containing spaces |
| UV-03 | Tool install/run/upgrade/uvx ALLOW and BLOCK; native child error propagation |
| UV-05 | Direct command/script/module/stdin/`--with`/help/version |
| REPORT-01 | Exact local ALLOW/BLOCK identities, command and Git repository |
| LIFE-01 | Allowed/blocked invocation listener and temporary-file cleanup |

Baseline commands disable ambient uv configuration with `UV_NO_CONFIG=1` so
registry selection cannot be changed by host or ancestor configuration.

Every protected case checks mode-specific exits, exact public package policy
identity, installed state or tool output, and cleanup. Upgrade BLOCK preserves the
previous installed version. Tool versions are dependency-free, so the discovery
manifest's selected package is the complete tool graph. Normal verifiers remain
live; reports retain their findings and failures.

Direct cases supply proxy mode but must bypass interception. The child probe
checks arguments, stdin, selected original environment and exit7. A real `--with`
download succeeds despite a target BLOCK list, records no policy evaluation, and
preserves the intentionally unprotected `uv run` boundary. Non-network direct
cases use an invalid upstream proxy and missing CA to detect accidental proxy
setup. These cases have registry profile `none`; no public-registry coverage is
credited to them. Missing-proxy cases record `REJECTED`, and direct cases record
`BYPASS`, rather than claiming a protected policy ALLOW.
