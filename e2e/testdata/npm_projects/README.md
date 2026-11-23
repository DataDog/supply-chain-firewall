# npm projects and command boundaries

This suite uses real public npm metadata, real pinned npm executables, and the
unaltered GoReleaser SCFW binary. It extends npm graph cache's native graph discovery with
an independently selected version of the required leaf, allowing a project to
install two versions of the same package. Discovery retains exact versions,
publication timestamps, native lockfiles, tarball URLs and integrity, then
revalidates them before each case. A changed or unavailable input fails the run;
execution never chooses a replacement package to make an assertion pass.

Every case first runs its command directly with the same npm/Node pins in a
separate isolated project/cache. SCFW's installation must match that native
installation, or satisfy the explicit BLOCK/unsupported-version boundary. Public
packages are checked against discovered artifact integrity in npm's lockfile;
local workspace/path packages are identified separately. The target oracle is
native installed package identity and path, including nested duplicate versions
and changes from a previously installed version. Policy reports are checked
separately from installed state. A manager failure must retain its native exit
and diagnostic without becoming a policy BLOCK.

The suite registers 70 cases. Both modes run the following modern npm variants:

| Scenario | Variants |
| --- | --- |
| NPM-02 | ALLOW/BLOCK from manifest with/without a lock; development and production selection (the production finding targets the omitted development package and must not block); an explicit global target under NODE_ENV=production with a case-local prefix; duplicate versions; upgrade and downgrade from an existing installation |
| NPM-03 | ALLOW/BLOCK for workspaces, a local file dependency with a real public dependency, and a harmless final-project lifecycle marker |
| NPM-04 | ALLOW/list-BLOCK npm ci; help, version, and dry-run with a finding that must not become a package evaluation |
| CORE-14 | Unresolvable version with native ETARGET; an allowed installation whose final-project hook fails with the native exit |
| CORE-11 | Genuine npm 6.x inspected installation rejection in resolution, real artifact BLOCK in proxy, and informational version commands in both modes |

Set `npm-projects-v7` for verified npm 7+ project cells. Set
`npm-resolution-pre7` for the dedicated exact npm 6.x guard cell. The other
version group's cases emit explicit N/A, rather than masquerading as passing
executions. The initial required pins are npm 7.0.0/Node 14.21.3,
npm 10.9.9/Node 22.23.3, and npm 6.14.18/Node 14.21.3. Do not infer support for
unverified manager/runtime combinations. Only native OS/architecture execution
counts toward the matrix; cross-building alone does not exercise a platform.

Resolution BLOCK preserves the original manifests, lock (including its absence),
and installed package state. Proxy BLOCK requires target absence and makes no
rollback claim. Resolution `npm ci` runs uninspected, even with an exact finding;
proxy `ci` protects downloaded artifacts. Help/version/dry-run may initialize a
proxy without evaluating an artifact. npm's minimum guard applies to inspected
resolution commands; proxy must not invent this guard.

`projects.json.tmpl` supplies the project manifests. `inspect_project.cjs` reads
installed metadata and never changes the project. `final_install.cjs` is the only
controlled executable fixture: it writes a harmless marker only when its working
directory is the original final-install project, and optionally returns 23 to
exercise a manager failure after ALLOW. This does not claim that dependency
resolution cannot execute code elsewhere. Public package scripts are disabled
for the other cases; the discovered package pool itself excludes install hooks.
Private-source NPM-03 variants require separate registry credentials and fixtures.

From the repository root, with provisioned exact manager/runtime/Git paths in a
copy of the shared matrix example and `suites: ["npm-projects"]`:

```sh
export SCFW_E2E_BINARY=/absolute/path/to/preserved-goreleaser-artifact/scfw
export SCFW_E2E_MATRIX=/absolute/path/to/npm-project-matrix.json
export SCFW_E2E_CELL=linux-arm64-npm7-node14
export SCFW_E2E_SUITES=npm-projects
export SCFW_E2E_OUTPUT=/absolute/path/outside/checkouts/npm-project-run-001
export SCFW_E2E_DISCOVERY="$SCFW_E2E_OUTPUT/discovery.json"
go test -tags=e2e ./e2e -run '^TestPlan$' -count=1
go test -tags=e2e ./e2e -run '^TestDiscover$' -count=1
go test -tags=e2e ./e2e -run '^TestE2E$' -count=1 -timeout=30m
```

Run each exact cell with its own discovery, keep first-failure output, and use a
new execution directory for a rerun with the same retained discovery. Retain the
binary outside `dist` so concurrent clean builds cannot remove it. All results
include command argv/output, selected metadata, policy, installed state, project
snapshots, and temporary-directory/listener cleanup. Required repository lint,
tagged vet, offline harness tests and GoReleaser build precede execution.

At baseline `05bf719`, native Linux ARM64 runs with npm 7.0.0 and 10.9.9 expose
two resolution defects: omitted development packages are evaluated (and can
incorrectly block a production-only install), and root workspace dependencies
are installed without evaluation. These cases deliberately remain FAIL until
separate production fixes satisfy the same assertions. The corresponding proxy
cases retain the intended behavior. A failing applicable case must never be
converted to N/A or an expected failure to publish a green suite.

Global production cases install only under the isolated case prefix. They check native and wrapped installed identity, exact policy selection, public tarball download URLs, and unchanged local project files; npm global installs do not create a project lockfile.

Production no-save cases bootstrap a native lock with a dev-only package, then explicitly install it with --save-prod --no-save --omit=dev. They require the selected package and its dependencies to be evaluated, and preserve original manifest/lock bytes for both ALLOW and BLOCK.

The paired --save-dev --no-save --omit=dev variants verify the opposite selection: the explicitly named dev-only graph remains omitted, including with an exact BLOCK finding, while the required production package is evaluated and installed.
