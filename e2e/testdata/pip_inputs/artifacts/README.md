# public pip artifact and requirement inputs

`pip-artifact-inputs` registers 30 cases: ALLOW/BLOCK for wheel, sdist, direct URL,
nested requirements/constraints, and extras/markers in both modes, plus
proxy-only download-wheel, download-sdist, build-sdist, public find-links,
and remote requirements.

Discovery uses the parent suite's real pip graph resolution for public
python-slugify and its required text-unidecode dependency. It then finds the
same root's public sdist and asks the pinned pip to resolve its `unidecode`
extra. The selected exact versions, native reports, public metadata, artifact
URLs/hashes and timestamps are retained and revalidated. Inputs remain pip's
responsibility. Constraint templates pin the discovered graph; contradictory
markers demonstrate that only the selected requirement set is installed.

Only `remote.txt.tmpl` is served from a loopback origin because the test needs a
custom requirement document. The document references actual public downloads;
the server cannot serve an artifact. Redirect/compression, private-index and
forced-transport variants belong to their network PRs. Public find-links uses
both projects' actual PyPI Simple pages with `--no-index`.

Install assertions check exact metadata, imports and pip's public artifact
hashes. Download assertions check exact public bytes. Builds check the generated
wheel metadata and retain its digest separately from the source digest. Target
and build dependency evaluations remain separately visible in policy records.
Resolution may run sdist metadata before policy; these tests do not claim that
blocking prevents metadata execution or rolls back manager work.

The negative variants use exact local findings against a required distribution:
root for wheel/sdist/direct URL/output commands, required leaf for nested,
extras and remote requirement inputs. BLOCK must have a matching policy record
and keep the required package or output absent; native resolver failure alone
never passes as a policy block.

Run with an exact manager/runtime cell that enables `pip-artifact-inputs` and both modes:

```sh
export SCFW_E2E_BINARY=/absolute/path/to/goreleaser/scfw
export SCFW_E2E_MATRIX=/absolute/path/to/matrix.json
export SCFW_E2E_CELL=your-exact-pip-cell
export SCFW_E2E_SUITES=pip-artifact-inputs
export SCFW_E2E_OUTPUT=/absolute/path/outside/source/new-run
export SCFW_E2E_DISCOVERY=$SCFW_E2E_OUTPUT/discovery.json
go test -tags=e2e ./e2e -run '^Test(Plan|Discover|E2E)$' -count=1 -timeout=25m
```

Fixture inventory: requirement/constraint templates, the extra/marker template,
the remote document, and a read-only built-wheel metadata inspector. Offline
report assertions reuse the parent graph's named valid/invalid report fixtures.
Required live validation: pip 22.2, 22.3 and a current exact pin. The below-minimum
negative and interpreter/configuration/lifecycle variants belong to pip config lifecycle.
