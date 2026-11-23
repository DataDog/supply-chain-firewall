# npm graphs, versions and cache boundaries

Suite `npm-graph-cache` registers 16 cases: each variant below in resolution and proxy
modes, with the local backend and public npm registry. Enable `npm-graph-cache` in the
chosen matrix cell's `suites`. No npm or Node version is silently skipped.

| Scenario | Variants |
| --- | --- |
| CORE-03 | `graph-allow`, `transitive-block` |
| CORE-04 | `version-invocations` (BLOCK first version, ALLOW second, BLOCK first again) |
| CORE-13 | `cold-artifacts`, `metadata-warm-artifacts-cold`, `artifact-warm-offline` |
| CORE-15 | `already-satisfied`, `empty-project` |

`npm.json` selects a small public root and required leaf. Discovery selects two
eligible root releases, resolves each with the exact cell's native npm, and
retains lockfiles, commands and registry snapshots. `selection.json` is referenced
by a SHA256 in the discovery manifest; native graphs, artifacts, freshness and
required edges are checked before installation. The leaf never appears in the
protected command's arguments. Every successful full installation checks both
installed package identities and lockfile artifact URLs/integrities.

Only named cache cases reuse their own priming step. `inspect_cache.cjs` reads and
verifies content through that npm installation's bundled `cacache`; this works
with npm7, which has no `npm cache ls`. Metadata priming uses native `npm view`
and proves both tarballs absent. Artifact priming installs through SCFW, then
removes `node_modules` before an `--offline` install with an exact BLOCK finding.
Resolution still evaluates the packages; proxy mode records no new policy
observation when npm reuses cached bytes. This is an artifact-coverage boundary,
not a new successful proxy evaluation or a claim that SCFW verifier services are
offline. Public server-side request counts are unavailable; retained npm HTTP
logs and cache contents provide manager-side download evidence. Proxy BLOCK does
not assert global rollback. Already-satisfied and empty-project commands check
that no package evaluation is reported.

`responses.json` contains native-lock shapes for the required-edge, missing-edge,
wrong-artifact and missing-leaf offline assertions. No public registry is replaced.

After setting the documented `SCFW_E2E_BINARY`, `SCFW_E2E_MATRIX`, `SCFW_E2E_CELL`,
`SCFW_E2E_OUTPUT` and `SCFW_E2E_DISCOVERY` inputs to fresh absolute paths:

```sh
export SCFW_E2E_SUITES=npm-graph-cache
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```
