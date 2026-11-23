# Controlled policy API with public registry installs

`policy-api` covers REPORT-01 ALLOW/BLOCK decisions for npm, pip and Poetry in
resolution/proxy modes and uv in proxy mode: 14 applicable manager/mode/decision
cases. The actual release-built CLI posts to the HTTPS evaluate/report endpoints
using `DD_SITE=scfw.test` and explicit dummy API/application keys. Only policy
responses are controlled; package metadata and artifacts come from public npm or
PyPI. Native installs run first in separate projects/caches to establish package
and runtime eligibility.

The fixture captures bounded request/response bodies and verifies TLS,
authentication, request types/UUIDs, noninteractive evaluation, exact package
identity/source/publication, command/executable/working directory/hostname,
installation timestamp, credential-free Git repository, action and matched policy.
Poetry resolution reports the canonical PyPI release URL and latest-file timestamp;
artifact-aware paths report the exact downloaded artifact URL and upload time.
A resolution command sends one evaluation/report pair; a proxy command sends that
pair for the single observed package identity. Installed state is independently
checked; a report is never treated as proof of installation. The suite also checks
SCFW cleanup and closes the policy listener on failure.

## Disposable Linux worker

The checked-in Dockerfile pins its Debian base. It installs Git, OpenSSL and public
CA roots; the worker records their actual versions. Provide externally provisioned
exact manager/runtime paths, a native GoReleaser SCFW artifact, and a compiled
native tagged test runner. The scripts mount those inputs read-only, mount only the
selected output directory writable, and run as the invoking UID without container
capabilities. Their only DNS change is a private container hosts entry. The fixture
CA is constrained to `api.scfw.test` and appended to a child-only public CA bundle;
host trust stores are never modified.

The matrix cell needs `controlled-policy-api` in `capabilities` and `policy-api` in
`suites`, as well as the usual native OS/architecture, exact manager/runtime/Git
pins and supported modes. Missing worker provisioning is an infrastructure failure.
Use the Git version installed inside the image, not the host's Git pin. Record
verified package versions whenever rebuilding the image changes that pin.

```sh
docker build -t scfw-policy-worker e2e/testdata/policy_api
goreleaser build --snapshot --clean
# Copy the matching artifact to an immutable path outside the checkout.
go test -tags=e2e ./e2e -c -o /absolute/manager-root/policy-evidence/e2e.test
export SCFW_E2E_BINARY=/absolute/manager-root/policy-evidence/scfw
export SCFW_E2E_TEST_BINARY=/absolute/manager-root/policy-evidence/e2e.test
export SCFW_E2E_MATRIX=/absolute/manager-root/policy-evidence/matrix.json
export SCFW_E2E_CELL=your-exact-cell-id
export SCFW_E2E_OUTPUT=/absolute/manager-root/policy-evidence/fresh-cell-output
export SCFW_E2E_DISCOVERY="$SCFW_E2E_OUTPUT/discovery.json"
sh e2e/testdata/system/policy-fixture-worker.sh \
  scfw-policy-worker /absolute/checkout /absolute/manager-root /absolute/tool-root
```

All matrix executables/runtimes and both binaries must be reachable beneath the
read-only manager/tool mounts. Existing environments with absolute Python symlinks
need their original interpreter path mounted too. The runner executes `TestPlan`, discovers only when the supplied manifest path
does not exist, and executes `TestE2E`. Replays reuse the original manifest; never
rediscover to conceal a failed SCFW assertion. Output includes registry discovery,
preflight versions, native/SCFW commands, HTTP exchanges, installation state,
fixture certificates, before/after host DNS/CA digests and `worker-cleanup.json`.
Each run needs a new output path; prior evidence is preserved. Containers are
removed on both successful and failed invocations.

## Native macOS prerequisite

The Go fixture helper is portable, but this change's Docker recipe proves Linux
execution only. Native macOS validation is pending future GitHub Actions runners. Those jobs need
a separately provisioned disposable native VM/user:
`api.scfw.test` must resolve only to loopback, port 443 must be available to the
fixture, and the generated fixture root must be trusted by that worker's native
keychain. Go's native macOS API client does not gain that trust from
`SSL_CERT_FILE` alone. Preserve initial keychain/DNS state and restore it or discard
the disposable worker after success or failure; do not configure a developer host.

`policy-fixture-certificates.sh OUTPUT PUBLIC_CA_BUNDLE` only generates certificate
files and a bundle. After the operator provisions native trust, supply
`SCFW_E2E_POLICY_WORKER=disposable` and `SCFW_E2E_POLICY_TLS=/absolute/OUTPUT` alongside
the normal harness inputs, then invoke the four standard harness entry points.
The directory must contain `ca.crt`, `server.crt`, `server.key` and `ca-bundle.crt`.
The Actions provisioning step must retain the original hosts file and native
keychain/trust settings, install only this job's fixture root, and reserve loopback
port 443. An unconditional teardown step removes that root by its recorded
certificate fingerprint, restores the saved DNS/trust state, and retains cleanup
evidence even when the test process fails. Linux containers on macOS do not count
as native macOS validation.

Native macOS keychain/bootstrap/teardown validation remains an explicit prerequisite,
not a passing cross-build or a successful skipped test.

`responses.json.tmpl` contains actual successful API response shapes. Named
`requests.json` cases exercise rejected transport/report evidence offline. Malformed
or failing API responses are outside this suite's baseline scope.
