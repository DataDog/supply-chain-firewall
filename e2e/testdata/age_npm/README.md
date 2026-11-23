# public npm publication age

This suite registers eighteen `LOCAL-03` cases: each variant below runs in both
resolution and actual proxy mode against the unchanged release-built SCFW CLI.
Every case starts with fresh npm artifacts, SCFW data and user configuration.
Normal OSV and malware services remain live. No findings list is created.

| Variant | Minimum age environment | Package outcome | Resolution action | Proxy action |
| --- | --- | --- | --- | --- |
| recent-default | unset | WARN | BLOCK, exit0 | ALLOW |
| recent-allow-warning | unset | WARN | ALLOW | ALLOW |
| recent-block-warning | unset | WARN | BLOCK, exit1 | ALLOW |
| old-default | unset | ALLOW | ALLOW | ALLOW |
| recent-disabled | 0 | ALLOW | ALLOW | ALLOW |
| recent-explicit24h | 24 | WARN | BLOCK, exit1 | ALLOW |
| recent-explicit1h | 1 | ALLOW | ALLOW | ALLOW |
| recent-invalid-negative | -1 | WARN | BLOCK, exit1 | ALLOW |
| recent-invalid-noninteger | invalid | WARN | BLOCK, exit1 | ALLOW |

Invalid values must emit the fallback diagnostic and a real24h age finding.
Warning cases require exactly the target's `PackageAgeVerifier` WARNING; other
live findings/failures remain failures with retained reports, never green skips.
Reports retain WARN separately from resolved ALLOW/BLOCK. Installed identity and
lockfile tarball URL/SHA512 integrity must match discovery. Resolution BLOCK also
preserves the original manifest/lock. Cleanup verifies temporary paths/listeners.

`candidates.json` is a bounded benign project-name pool, queried in declared order
using full public packuments. The selected stable leaf release must be compatible
with the pinned Node runtime, have no install scripts, and have age65m–22h. The
lower bound allows an explicit1h control; the upper bound leaves2h for queueing,
execution and clock skew under the unchanged default24h threshold. An old public
control comes from npm baseline discovery. Types-only recent packages need no import;
the real npm install, installed package identity and artifact integrity are checked.

`search.json` retains every fetched metadata snapshot/digest and version rejection,
including an empty search's PRECONDITION_UNAVAILABLE status. The candidate manifest
adds optional schema-v1 `age_threshold_hours` and `applicable_cells` fields and
retains publication time, exact version, SHA512, observation and latest valid start.
Discovery is cell-specific. Before every install, revalidation checks availability,
identity, time, integrity and Node compatibility. The age condition must also hold
throughout SCFW's actual start/end interval. Expiry is a precondition failure;
SCFW assertions never select another package or widen the threshold.

`responses.json` contains offline registry fixtures only. `policy.json` contains
offline report cases proving a warning cannot be replaced by a list finding,
wrong version/threshold, another advisory or verifier failure. These fixture bytes
are never served to an E2E install. Existing npm baseline project and installed-state
fixtures are reused without modification.

Provide a matrix cell with `manager=npm`, exact executable/Node/Git pins,
`modes=["resolution","proxy"]` and `suites=["npm-recent"]`. Set the paths described
in ../../README.md, with a fresh output directory outside the checkout, then run:

```sh
export SCFW_E2E_SUITES=npm-recent
# SCFW_E2E_BINARY is the matching goreleaser build --snapshot --clean artifact.
# SCFW_E2E_MATRIX, SCFW_E2E_CELL, SCFW_E2E_OUTPUT and SCFW_E2E_DISCOVERY are required.
go test -tags=e2e ./e2e -run '^TestHarness' -count=1
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```

Required native validation tuples are npm7.0.0/Node14.21.3 and
npm10.9.9/Node22.23.3. Discover separately for each cell. Preserve first-failure
outputs when investigating; a stale manifest needs a new discovery ID before
execution and cannot reproduce an earlier package age.
