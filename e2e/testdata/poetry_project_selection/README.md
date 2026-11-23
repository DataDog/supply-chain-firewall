# Poetry selected-project regression

Suite `poetry-project-selection` covers POETRY-04 with a real selected project
and an unrelated caller project, each with its own Git origin and virtualenv.
It runs ALLOW and exact-list BLOCK in resolution and proxy modes for `--project`,
`--project=`, `-P`, attached `-P`, relative `--project` after `--directory`, a
selected subdirectory, and a symlink followed by `..` (28 cases per modern cell).

A successful `add` must modify the selected project only, retain the exact public
artifact, report that project's repository, and install into the environment
identified by a read-only native `env info --executable` control using the same
selectors. Poetry can normalize a symlink/.. virtualenv path differently from
its physical manifest path; the suite preserves that native behavior and proves
the other isolated environment remains empty. Resolution
BLOCK must preserve both live manifests/locks and leave both environments empty.
The same public candidate and fixtures as `poetry-baseline` are reused, including
its native project bootstrap, findings template, and installed-state inspector.
No synthetic manager or registry is used. Proxy BLOCK retains its existing
partial-progress semantics; the targeted package must still be absent.

Enable this suite in the exact Poetry cell of the baseline matrix and set the
runner's absolute `SCFW_E2E_*` inputs, then run:

```sh
export SCFW_E2E_SUITES=poetry-project-selection
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```
