# Poetry baseline suite

Run from the repository root using the real GoReleaser artifact and real Poetry.
Poetry must be installed separately from each project; provide pinned Python with
`venv` and Git. Copy this directory's `matrix.json` outside the checkout, replace
all executable paths and native OS/architecture, and verify the exact versions.
The pilot pins Poetry 2.0.0 and 2.5.1 with Python 3.12.10; it is not the full CI
support matrix. No credentials or controlled registry are required.

```sh
make lint
make golangci-lint
goreleaser build --snapshot --clean
go test -tags=e2e ./e2e -run '^TestHarness' -count=1
go vet -tags=e2e ./e2e
export SCFW_E2E_BINARY=/absolute/path/to/dist/scfw_linux_arm64_v8.0/scfw
export SCFW_E2E_MATRIX=/absolute/path/to/poetry-matrix.json
export SCFW_E2E_CELL=linux-arm64-poetry-2.0.0-python-3.12.10
export SCFW_E2E_SUITES=poetry-baseline
export SCFW_E2E_OUTPUT=/absolute/path/outside/checkouts/poetry-001
export SCFW_E2E_DISCOVERY="$SCFW_E2E_OUTPUT/discovery.json"
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```

Repeat with the second cell and a new output directory. Preserve failed attempts.
Discovery shares pip baseline's old PyPI candidate selection and per-case revalidation.
Native Poetry lock bootstrap uses a different cache from the protected command,
so the real wheel must pass through SCFW on each install. Project and manager
environments, configuration, caches, SCFW_HOME and temporary paths are isolated.

The suite registers 30 variants:

| Source | Variants |
| --- | --- |
| CORE-01 | install ALLOW in resolution and proxy modes |
| CORE-02 | install BLOCK with/without --error-on-block in both modes |
| CORE-10 | unset, 0, true and 1 proxy flag values, using BLOCK exits to distinguish modes |
| CORE-12 | explicit Poetry executable and project paths containing spaces, both modes |
| POETRY-01 | add ALLOW/BLOCK in both modes; install also covered by CORE-01/02 |
| POETRY-05 | run, --version, --help, help install, list, about, install --help, no command |
| REPORT-01 | ALLOW/BLOCK identity, executable, command, timestamp and Git repository, both modes |
| LIFE-01 | allowed/blocked proxy add cleanup followed by a fresh allowed install |

ALLOW checks installed distribution metadata, import location/version, and the
fresh Poetry artifact cache against the discovered public wheel SHA-256. BLOCK
checks absence and the exact local finding. Resolution BLOCK preserves manifest
and lock; snapshots remain in evidence. Allowed add must update both files.
Cleanup checks temporary lock projects, SCFW temporary material and closed
listeners. A local report is a policy record, not proof of installation.

Direct commands are compared with a native Poetry invocation under deliberately
unusable proxy/CA settings. The local child probe exposes stdin, arguments,
allowlisted routing/trust environment, stderr and exit 7. No policy report,
invocation proxy or leftover SCFW material is allowed. These cases perform no
registry installation and have no discovery key.

Fixtures are a real Poetry project template and two observation scripts. The
scripts neither emulate a manager nor replace registry packages. Offline helper
checks reject changed/deleted project files and missing/mismatched wheel bytes.
