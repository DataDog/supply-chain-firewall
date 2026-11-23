# Poetry and uv dependency graphs and cache boundaries

Suite `poetry-uv-graphs-cache` registers nine variants for Poetry resolution,
Poetry proxy, and uv proxy. Enable this suite in an exact pinned cell; the
sample `matrix.json` covers Poetry 2.0.0/2.5.1 and uv 0.13.4 on native Linux arm64.
Replace executable paths and native platform values with the provisioned worker.
Python 3.11+ supplies `tomllib` for the read-only native lock inspector.

| Scenario | Variants |
| --- | --- |
| CORE-03 | `graph-allow`, `transitive-block` |
| CORE-04 | `version-invocations`: BLOCK one version, ALLOW another, BLOCK the first again |
| CORE-13 | `cold-artifacts`, `metadata-warm-artifacts-cold`, `artifact-warm-http`, `offline-artifact-reuse` |
| CORE-15 | `already-satisfied`, `empty-project` |

Discovery reuses the public `python-slugify`/`text-unidecode` graph candidate pool
from the pip graph suite. It chooses two old, compatible universal root wheels,
generates native lockfiles with the exact selected manager, and checks the
required leaf edge, versions, public registry and wheel SHA256 against retained
PyPI metadata. Only the root appears in project dependencies. Discovery retains
each generated manifest and lock, command output and selected artifact evidence.
No lock is copied from another manager version. The test commands execute the
unchanged GoReleaser SCFW artifact, real Poetry `install`, and real uv `sync`.

Each version invocation uses a new project, venv and manager cache; only the
SCFW verifier home is shared. The target BLOCK must appear in policy reports and
be absent from the environment. Successful installs must contain both exact
versions and import both modules. Resolution denial preserves manifest and lock
bytes. Proxy denial makes no rollback promise for unrelated allowed packages.

Cold cases start with empty artifact caches. Metadata priming regenerates the
native lock and checks that registry metadata exists while artifacts remain
absent. Artifact priming installs through SCFW, then retains cache inventories;
Poetry wheel SHA256 must match discovery, while uv retains extracted wheel files
and native download diagnostics for the hashed artifacts in its frozen lock.
A frozen uv install can fetch the locked wheel directly without a simple-index
cache. Warm reuse removes the venv and adds an exact root finding: resolution
still blocks the installation target, while proxy evaluates no package when the
manager reuses the artifact cache. The satisfied-environment case preserves its
venv and expects no package evaluation in either mode.

`offline-artifact-reuse` uses a local rejecting CONNECT proxy only to forbid
connections to the selected public artifact host. Metadata and verifier
connections are forwarded to the real services unchanged, and every CONNECT is
recorded. This isolates the artifact-network condition; it is not a claim that
SCFW works fully offline. uv additionally receives `--offline`; Poetry has no
native offline switch. The guard must observe zero artifact attempts. Default
verifiers stay enabled. Public server request counts are unavailable; reports,
manager diagnostics, cache inventories and the scoped guard provide client-side
evidence. No registry response or package is substituted by a fixture.

Fixtures:

- `pyproject.toml.tmpl` and `configurations.toml.tmpl`: root-only and empty native projects.
- `inspect_lock.py`: read-only Poetry/uv lock inspection; rejects optional or non-public graph inputs.
- `inspect_cache.py`: cache file hashes, metadata presence, and reusable artifact presence.
- `responses.json`: required edge, missing leaf, optional leaf, wrong version/hash, and duplicate-node assertions.
- `matrix.json`: exact manager examples, with operator-supplied tool paths.

Set `SCFW_E2E_BINARY`, `SCFW_E2E_MATRIX`, `SCFW_E2E_CELL`,
`SCFW_E2E_DISCOVERY`, and `SCFW_E2E_OUTPUT` to absolute paths and a fresh evidence
directory as described in the E2E runner README, then run:

```sh
export SCFW_E2E_SUITES=poetry-uv-graphs-cache
go test -tags=e2e ./e2e -run '^TestHarness' -count=1
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```

Keep `GIT_DIR`/`GIT_WORK_TREE` unset for tests. A host that needs a build-VCS
worktree workaround can add `-buildvcs=false` to test compilation only.
