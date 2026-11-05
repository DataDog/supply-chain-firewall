# Repository guide

Supply Chain Firewall (`scfw`) is a Go command-line application that protects package-manager operations. It resolves the packages an npm, pip, or Poetry command would install, asks the Datadog Code Security API to evaluate those packages, and then allows, warns about, or blocks the original command.

## Repository structure

- `scfw/main.go` is the executable entry point. Keep it limited to process-level setup and handing control to the CLI package.
- `scfw/internal/cli` defines Cobra commands and owns user-facing command orchestration: configuration, diagnostics, package-manager selection, policy outcomes, prompts, and running the approved command. Generic proxy configuration and lifecycle-context wiring stay in `cli/proxy.go`; PyPI proxy orchestration and invocation-scoped discovery/resolution state live in `cli/proxy_pypi.go`; ecosystem-independent policy evaluation of resolved `pm.Package` values, decision caching, reporting, and presentation stay in `cli/proxy_evaluation.go`.
- `scfw/internal/build` owns build-time metadata such as the application version. Release builds inject these values through GoReleaser.
- `scfw/internal/ddapi` owns Datadog authentication, HTTP transport, and the Code Security API implementation of the `evaluation` interfaces (policy evaluation and run reporting). Package-manager-specific behavior does not belong here.
- `scfw/internal/evaluation` defines the policy evaluation and reporting domain: shared outcome/report types and the `Evaluator`/`Reporter` interfaces that the Datadog and local backends implement.
- `scfw/internal/evaluation/local` implements local evaluation (running the `verifier` package's verifiers) and local run reporting to a JSON Lines log file.
- `scfw/internal/verifier` defines the local package verification framework: the `Verifier` interface that concrete verifiers implement. Subpackages `verifier/osv` (OSV.dev advisories), `verifier/ddmalware` (Datadog malicious-software-packages-dataset), `verifier/age` (recently-published packages), and `verifier/list` (user-provided findings lists) each implement one verification source.
- `scfw/internal/proxy` owns the short-lived, loopback-only HTTP/HTTPS proxy that `scfw run` routes package manager traffic through, using goproxy's CONNECT interception with request-scoped response hooks and bounded body inspection before forwarding. It also owns generic proxied-command execution in `proxy/run.go` (child-only environment merging, streams, signals, job control, and cleanup) and TLS material loading from PEM files or CA directories in `proxy/tls.go`; adapters implement its `CommandConfigurer` interface. Its per-run certificate authority and interception certificates are generated with the Go standard library only. It is generic: ecosystem-specific request classification, metadata parsing, and package-manager-specific configuration do not belong here.
- `scfw/internal/home` resolves SCFW's home directory (`SCFW_HOME`, else a directory under the user's cache directory), where verification data is cached and the local log is written.
- `scfw/internal/ecosystem` defines shared ecosystem identifiers and package-name normalization, resolves npm publication data, and dispatches registry operations that are independent of a particular package-manager executable.
- `scfw/internal/ecosystem/pypi` owns distribution request classification, JSON metadata observation and discovery, and publication-data resolution. HTML metadata streams through without body inspection; recognizable distribution filenames and observed JSON identify downloads before a caller-provided artifact callback performs policy evaluation.
- `scfw/internal/git` discovers local Git repository metadata and removes credentials before reporting.
- `scfw/internal/pm` owns the shared package and package-manager abstractions (including the `ProxyRunner` interface that embeds the core proxy's command-configuration contract), version handling, and reusable collections. Keep this package independent of concrete package managers.
- `scfw/internal/pm/npm`, `scfw/internal/pm/pip`, and `scfw/internal/pm/poetry` each own integration with that executable: supported commands and versions, dry-run or temporary-project behavior, output parsing, and conversion into the shared `pm.Package` model.
- Tests live beside the code they cover as `*_test.go` files. Store registry payloads, package sources, configuration samples, and process scripts in the owning package’s `testdata` directory and read them from tests. Group related JSON responses as named cases in `responses.json`; keep templates and executable sources as separate files. `.tmpl` fixtures retain runtime substitutions for temporary URLs and paths. Add or update focused tests with every behavioral change.
- `.goreleaser.yml` is the authoritative cross-platform release-build configuration. Root-level files such as `go.mod`, `go.sum`, `Makefile`, and `.golangci.yml` define dependencies and development tooling.
- `.github` contains CI, release, and repository automation, with supporting scripts and their tests in `.github/scripts`; `images` contains documentation assets.

## Structure maintenance rule

Keep this guide accurate as part of every structural change. In the same change that creates, removes, renames, moves, or materially repurposes a package or top-level directory, update the structure section above to state its responsibility and boundaries. A new package must have one clear, cohesive responsibility, live at the narrowest appropriate scope, and avoid duplicating responsibilities already assigned here. If its purpose cannot be described in one concise sentence, reconsider the package boundary before adding it.

Preserve the existing separation of concerns: the CLI orchestrates (including evaluation-mode selection), `evaluation` provides shared evaluation/reporting abstractions, `ddapi` communicates with Datadog, `evaluation/local` and `verifier` implement local evaluation, `ecosystem` communicates with registries, `proxy` provides generic traffic interception, `pm` provides shared domain abstractions, and each `pm/<manager>` package implements one package-manager adapter. Do not put manager-specific parsing in `pm`, API transport in `cli`, or CLI presentation in lower-level packages.

Within a package, isolate ecosystem-specific behavior in explicitly named files (for example, `proxy_pypi.go`). Shared orchestration should select and wire ecosystem implementations without embedding their protocol logic. Ecosystem protocol handling belongs in the corresponding `ecosystem/<name>` package; policy orchestration, reporting, and presentation stay in `cli`.

## Validation

Run relevant unit tests while developing. Before considering any change complete, run both repository lint targets and resolve every reported issue:

```sh
make lint
make golangci-lint
```

Keep the local `golangci-lint` version aligned with the version used by CI. Do not skip linting because a change appears small or because focused tests pass.

The required build validation for every completed change is:

```sh
goreleaser build --snapshot --clean
```

Use this GoReleaser build rather than substituting `go build` or `make`; it validates the supported targets and the release-time flags defined in `.goreleaser.yml`.
