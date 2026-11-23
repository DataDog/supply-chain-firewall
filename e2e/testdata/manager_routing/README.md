# Manager routing precedence and bypass boundaries

The `manager-routing` suite compares separate native and SCFW installs of the
same discovered public package. Every successful routing case has ALLOW and
exact-list BLOCK variants. Malformed proxy URLs have native-error and SCFW
setup-diagnostic checks. The evaluator remains local with its normal live sources.

| Scenario | Implemented variants |
| --- | --- |
| NET-09 | Domain suffix, near-boundary suffix, explicit default-port diagnostics and nondefault destination port match/miss, IPv4 match/miss, CIDR, and IP-with-port. |
| NET-10 | ALL_PROXY fallback; npm npmrc/environment/flag precedence and command-line noproxy interception; pip global/command/environment/flag precedence, explicit fallback, and no-proxy-env; Poetry empty-lowercase fallback; malformed proxy diagnostics. |
| UV-07 | HTTPS file proxy over environment, HTTP-only file proxy disabling HTTPS environment discovery, file bypass precedence, and explicit configuration-file routing. |

Native differences are explicit. npm ignores ALL_PROXY, treats bypass patterns as
literal domain suffixes, and does not interpret ports or CIDR. pip 22.1 and newer give a nonempty explicit proxy priority over environment
routing. Environment CA bundles still apply through 24.0; pip 24.1 disables
environment trust with a nonempty explicit proxy. pip 26.1.2 retains Requests' loose suffix
matching; pip 26.2 uses domain boundaries. An explicit pip
proxy is retained when the environment requests bypass. `no-proxy-env` configuration
is ignored before 26.2; the CLI flag requires the `pip-no-proxy-env` capability,
verified using native `pip --help`. The flag is absent on 26.1.2. uv file proxy
settings require the existing `uv-file-proxy` capability (verified on 0.13.4).

Most traffic goes directly to public npm/PyPI. Literal-IP and nondefault domain-port cases require a
loopback index because public registries do not expose those stable address forms. The index supplies the unmodified discovered npm packument or a Simple
page advertising only the discovered PyPI wheel, preserving public artifact URLs
and bytes. npm receives child-only `replace-registry-host=never` so it preserves
those advertised public tarball origins. The index rejects artifact paths. Its body, exact requests, endpoint, and narrow exception are retained.
No DNS, system proxy, keychain, or host trust configuration is modified.

Routing assertions use artifact-host traffic, which distinguishes manager
transfers from independent policy metadata lookups. BLOCK prevents that transfer;
its oracle is exact policy identity plus absent installed state. Address cases assert
index routing for both ALLOW and BLOCK. Python default-443 bypass rules reject
before manager execution because explicit and implicit :443 become identical on
the intercepted wire. Both native forms are exercised; diagnostics require no
policy record, installed artifact, or artifact-host traffic. Nondefault ports
retain positive ALLOW/BLOCK coverage. All phases retain both upstream logs and
separate native command/state evidence, even after failure. Original manager
configuration bytes must remain unchanged. uv's real invocation is observed to
retain the temporary merged configuration, verify replaced routing and preserved
index settings, and prove its removal after completion.

Adapt `matrix.json` to exact provisioned tool paths and the native worker. Run:

```sh
export SCFW_E2E_BINARY=/absolute/evidence/scfw
export SCFW_E2E_MATRIX=/absolute/evidence/matrix.json
export SCFW_E2E_CELL=linux-arm64-pip-26.2
export SCFW_E2E_SUITES=manager-routing
export SCFW_E2E_OUTPUT=/absolute/evidence/manager-routing-attempt1
export SCFW_E2E_DISCOVERY=$SCFW_E2E_OUTPUT/discovery.json
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=20m
```

Build the executable using `goreleaser build --snapshot --clean`. Preserve a
failed attempt and reuse its discovery manifest when rerunning fixed harness
code. Missing infrastructure, native control failures, and SCFW mismatches fail;
they are never successful skips. Both Linux and macOS require native acceptance
execution; this fixture does not infer one platform's outcome from another.

The `python-port-bypass` suite selects the six implemented port variants for each
Python manager. `pip-proxy-boundary` selects four implemented explicit-proxy and
fallback variants for the supported 22.2 floor and exact 24.0/24.1 and 26.2 boundary validation. These focused suites
reconcile complete planned case lists; they do not rely on Go subtest filters.
