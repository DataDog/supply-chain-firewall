# uv command operations

Select `SCFW_E2E_SUITES=uv-commands` with the shared runner. Copy this directory's
matrix outside the checkout, replace executable paths and exact native versions,
then run `TestPlan`, `TestDiscover`, and `TestE2E` as described in
`e2e/README.md`. Supply an unchanged GoReleaser artifact. Run
`go test -tags=e2e ./e2e -run '^TestHarnessUVCommands' -count=1` for offline checks.

The 39 registered variants are:

| Scenario | Variants |
| --- | --- |
| UV-01 | pip sync and compile: ALLOW and required-artifact BLOCK |
| UV-02 | add/remove/sync/lock/export/tree/build: ALLOW and required-artifact BLOCK; compile/lock/export/tree ordinary-index metadata-only boundaries |
| UV-04 | version bump, explicit value, no-sync, seeded venv flag/environment: ALLOW and required-artifact BLOCK; version read/dry-run/frozen flag/environment and unseeded venv direct boundaries |
| CORE-14 | native invalid-argument rejection before downloads; native build-backend failure after allowed backend download |

Every variant runs an independent native uv command first with a fresh home,
cache and project, then runs the same command through SCFW in a second isolated
environment. The suite checks manifest versions, exact lock identities and
artifact hashes, compiled/exported requirements, installed distribution metadata,
built wheel metadata, native error exit/diagnostics, policy records and proxy
cleanup. It records state after a blocked command without promising rollback of
uv's preliminary manifest changes.

Discovery selects a real old universal wheel from the maintained PyPI leaf pool,
and dependency-free old flit-core and pip wheels from public PyPI metadata.
Exact versions, URLs, SHA256 and upload timestamps are retained and revalidated.
No selected version changes after SCFW execution. Local source/configuration is
under this directory; Python reads installed metadata using the trusted runtime
with `-I -S`, without importing installed packages or processing startup hooks.

Ordinary-index compile/lock/export/tree may use PEP 658 metadata without fetching
a distribution. Those cases include an exact BLOCK finding and require successful
native-equivalent output with no package evaluation. Their separate artifact
cases use the selected public PyPI wheel's exact files.pythonhosted.org URL to
force an identifiable artifact request. This is a public-origin input condition,
not a substitute registry or fabricated publication date. The remove case starts
with the selected leaf and pinned flit-core, removes flit-core, and fetches the
remaining leaf in the fresh environment. Build uses a tiny local project and the
real public flit-core backend; its failure control omits the local module.

Seed cases require the declared `uv-seed-pip-only` capability and Python >=3.12,
where uv seeds pip alone. The recorded discovery timestamp minus 48 hours is
passed through `UV_EXCLUDE_NEWER`; the native control must install the selected
exact pip version before SCFW is tested. Python <3.12 requires a separate
multi-package seed contract and must omit this capability. Every other case
still runs. Supported uv versions must provide all listed commands/options;
missing tools or unsupported options fail rather than silently skip.

The baseline and older boundary cells use uv 0.13.4 and 0.9.0 with exact Python
3.12.10. Native macOS execution remains pending future GitHub Actions runners;
a cross-compiled release binary does not establish runtime acceptance. On those
runners provide native pinned uv/Python/Git and replace the example OS/architecture
and absolute paths. This suite needs no developer-host DNS or trust changes.
