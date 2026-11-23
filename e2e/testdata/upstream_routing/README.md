# Public-registry upstream routing

The `upstream-routing` suite runs twelve `NET-09` variants per manager (`npm`, `pip`,
`poetry`, and `uv`), all in proxy mode with the local evaluator:

| Variant | Native control and protected-operation expectation |
| --- | --- |
| `http` | Registry traffic uses the loopback HTTP forwarding proxy. |
| `https` | Registry traffic uses the HTTPS forwarding proxy with a child-only CA bundle. |
| `authenticated` | The forwarding proxy accepts only the fixture credentials. |
| `mixed-case` | Lowercase wins for npm/pip/Poetry; uppercase wins for uv, confirmed by native controls. |
| `mixed-name` | npm/pip/Poetry recognize `hTtPs_PrOxY`; uv ignores this nonstandard spelling. |
| `no-proxy-all` | Python managers bypass the upstream; npm treats `*` literally. SCFW still evaluates the package. |

Every variant has `allow` and `block` cases. An independently isolated native
installation must succeed first using the same discovered exact version. The
protected operation then installs that version or rejects its exact local finding.
Manager-specific baseline checks retain policy, installed state, artifact evidence,
and closed listeners/removed interception material. Route assertions select only
the installation command's time interval and public registry host, excluding
bootstrap and verifier traffic. Both selected and competing upstream logs remain
in evidence even after failure. Native controls have independent homes and caches.

These fixtures forward unchanged public npm/PyPI content. The HTTPS fixture
terminates only the connection to the forwarding proxy; CONNECT tunnels preserve
origin TLS. Each listener binds to loopback and accepts only the public registry
and verifier destinations used by these cases. Authentication failures and
unlisted destinations fail closed. No DNS, OS proxy, keychain, or system CA state
is changed. `roots.py` and `roots.cjs` read the pinned runtime's public trust roots (Python falls back to a read-only OS PEM bundle when its SSL context has no roots);
the test adds its ephemeral proxy certificate in a case-owned file and verifies
that file remains unchanged.

Create an absolute matrix from `matrix.json`, replacing executable/runtime/Git
paths and native OS/architecture. Both Linux and macOS native runners are required
for platform acceptance; running only one platform does not establish the other.
Use separate output and discovery paths for every cell/attempt:

```sh
export SCFW_E2E_BINARY=/absolute/evidence/scfw
export SCFW_E2E_MATRIX=/absolute/evidence/matrix.json
export SCFW_E2E_CELL=linux-arm64-pip-26.2
export SCFW_E2E_SUITES=upstream-routing
export SCFW_E2E_OUTPUT=/absolute/evidence/pip-routing-attempt1
export SCFW_E2E_DISCOVERY=$SCFW_E2E_OUTPUT/discovery.json
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```

Build the SCFW artifact with `goreleaser build --snapshot --clean` before running.
Missing tools, failed native controls, unavailable public registries, policy
mismatches, and incomplete route evidence fail the selected case. Offline harness
checks (`go test -tags=e2e ./e2e -run '^TestHarness'`) verify forwarding bytes,
authentication, destination restrictions, tunnel cleanup, and the route oracle.
