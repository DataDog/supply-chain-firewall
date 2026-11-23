# pip graphs, versions and cache boundaries

Suite `pip-graph-cache` registers 18 cases: each variant below in resolution and proxy
modes with the local backend. Enable the suite in the exact pinned matrix cell.

| Scenario | Variants |
| --- | --- |
| CORE-03 | `graph-allow`, `transitive-block` |
| CORE-04 | `version-invocations` (BLOCK first version, ALLOW second, BLOCK first again) |
| CORE-13 | `cold-artifacts`, `metadata-warm-artifacts-cold`, `artifact-warm-http`, `artifact-warm-offline` |
| CORE-15 | `already-satisfied`, `empty-requirements` |

`candidates.json` names a public root and required leaf plus import modules.
Discovery chooses two compatible old universal wheels, uses the exact cell's
native `pip install --dry-run --report` to resolve each graph, and retains
registry metadata, reports, command output and SHA256 references in the Selection
manifest. The native report must contain exactly two packages, the root must
unconditionally require the leaf, and only the root may be marked requested.
Install commands name only the root; a constraint pins the discovered transitive
version without making it a requested package. Artifact URL and SHA256, actual
installed distribution versions, and imports are independently checked.

Every invocation has fresh manager state except the named cache priming/reuse
steps. Version invocations retain only the policy/verifier home. Metadata priming
uses native `pip index versions`, and the read-only `inspect_cache.py` verifies
simple-index entries exist while both wheel bodies are absent. That script uses
the configured Python's vendored CacheControl key normalization and MessagePack
decoder, then reads the native layouts directly: pip22.2 stores HTTP bodies inline,
while newer pip uses separate HTTP-v2 bodies. It does not depend on that Python
having the same pip cache API as the selected manager. Metadata reads are bounded
to 17 MiB and bodies to 16 MiB; malformed or unsupported entries fail inspection.
Allowed public installs retain exact cached artifact SHA256 after execution. HTTP-warm reuse
removes installed state and adds an exact BLOCK: resolution still evaluates,
while proxy reports no new artifact evaluation when pip uses cached wheel bytes.

Pip has no `--offline` switch. The separate `public-pypi-primed-wheelhouse` profile
first installs publicly through SCFW, then uses native `pip download` to populate
a per-case wheelhouse. Every wheel is checked against the discovered public hash.
After installed state is removed, `--no-index --find-links` installs those exact
bytes locally. This is an explicit local-source coverage boundary, not a claim
that a public registry is reachable offline or that registry-only verifiers can
verify local file sources. Resolution retains its ALLOW reports and verifier
failures; proxy retains no new package policy observation. Default verifier
services remain enabled. Public server request counts are unavailable; native
pip stdout/stderr, cache contents, reports and wheel files provide client evidence.

The already-satisfied case needs a real venv because pip `--target` reinstalls.
It bootstraps that venv with `ensurepip`, installs the exact matrix pip pin from
public PyPI, verifies its version, and supplies its actual executable to SCFW.
The second invocation with an exact finding must preserve the installed packages
and report no package evaluation. Empty requirements similarly retain native
success with no targets. No shim or production test flag is used.

`responses.json` retains required-edge, optional-edge, missing-leaf, wrong-hash
and explicitly-requested-leaf report fixtures for offline graph assertions.

With documented `SCFW_E2E_*` inputs set to absolute paths and a fresh output:

```sh
export SCFW_E2E_SUITES=pip-graph-cache
env -u GIT_DIR -u GIT_WORK_TREE go test -buildvcs=false -tags=e2e ./e2e -run '^TestPlan$' -count=1
env -u GIT_DIR -u GIT_WORK_TREE go test -buildvcs=false -tags=e2e ./e2e -run '^TestDiscover$' -count=1
env -u GIT_DIR -u GIT_WORK_TREE go test -buildvcs=false -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```

`cache_formats.py` checks both layouts, missing entries, invalid serialization,
read bounds, and read-only behavior. The offline Go harness runs it when Python
and pip's decoder dependencies are available. It can also be run with each
provisioned interpreter directly:

```sh
python3 e2e/testdata/graph_cache/pip/cache_formats.py
```
