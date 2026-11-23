# Public PyPI age-policy checks

`pypi-recent` registers LOCAL-03 for pip and Poetry in resolution/proxy modes,
and uv in proxy mode. Each manager/mode has eight variants: default recent,
allow-on-warning, block-on-warning, old control, disabled zero, explicit 24 hours,
negative fallback, and noninteger fallback. Resolution warnings block by default;
`--allow-on-warning` permits installation. Proxy warnings permit installation.

Discovery retains PyPI's RSS release feed and searches at most eight maintained
projects plus forty feed projects. It selects a stable release with one compatible
universal wheel, no mandatory dependencies, and all release files younger than
22 hours. Only simple `extra == "name"` dependency markers are accepted as optional;
unknown markers and Python constraints are rejected. No extras are installed.
The source archive timestamps also constrain eligibility because resolution can
use the latest-file publication date. The old control is older than 48 hours.

A discovery manifest lists all compatible Python cells enabled for this suite in
the supplied matrix. Reuse that manifest across those cells. Each case retains
revalidated metadata and a manifest revision, uses a fresh manager cache and
isolated environment, and checks freshness immediately before and throughout the
SCFW invocation. Expiry or an empty candidate search fails with
`PRECONDITION_UNAVAILABLE`; use a new discovery output path before execution if
fresh evidence is required. Never rediscover to conceal an SCFW assertion failure.

The tests use the unchanged release-built SCFW binary and public PyPI installs.
No target findings list is created. Policy assertions require the exact age
verifier, severity, threshold and package identity; unexpected live findings or
verifier failures remain failures. Installed distribution metadata, pip's artifact
report, Poetry's downloaded-wheel digest and uv's verbose wheel identity supply
installation evidence. They also retain cleanup checks and Poetry project snapshots.

The `responses.json` and `policy.json` fixtures are only for offline harness tests;
synthetic dates never feed real installs. `candidates.json` supplies the maintained
public-project pool, not fixed package versions.

After provisioning exact manager/runtime pins in an absolute matrix file:

```sh
export SCFW_E2E_BINARY=/absolute/release-artifact/scfw
export SCFW_E2E_MATRIX=/absolute/matrix.json
export SCFW_E2E_CELL=your-exact-cell-id
export SCFW_E2E_SUITES=pypi-recent
export SCFW_E2E_OUTPUT=/absolute/evidence/discovery
export SCFW_E2E_DISCOVERY=/absolute/evidence/discovery/manifest.json
# Each enabled matrix cell must include pypi-recent in suites.
go test -tags=e2e ./e2e -run '^TestHarnessPyPI' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
# Use a fresh output directory for each compatible cell; keep the same manifest.
export SCFW_E2E_OUTPUT=/absolute/evidence/your-exact-cell-id
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```
