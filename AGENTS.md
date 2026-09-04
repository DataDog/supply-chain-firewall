# Repository guide

Supply Chain Firewall (`scfw`) is a Go command-line application that protects package-manager operations. It resolves the packages an npm, pip, or Poetry command would install, asks the Datadog Code Security API to evaluate those packages, and then allows, warns about, or blocks the original command.

## Repository structure

- `scfw/main.go` is the executable entry point. Keep it limited to process-level setup and handing control to the CLI package.
- `scfw/internal/cli` defines Cobra commands and owns user-facing command orchestration: configuration, diagnostics, package-manager selection, policy outcomes, prompts, and running the approved command.
- `scfw/internal/build` owns build-time metadata such as the application version. Release builds inject these values through GoReleaser.
- `scfw/internal/ddapi` owns Datadog authentication, HTTP transport, and the Code Security API implementation of the `evaluation` interfaces (policy evaluation and run reporting). Package-manager-specific behavior does not belong here.
- `scfw/internal/evaluation` defines the policy evaluation and reporting domain: shared outcome/report types and the `Evaluator`/`Reporter` interfaces that the Datadog and local backends implement.
- `scfw/internal/evaluation/local` implements keyless evaluation (running the `verifier` package's verifiers) and keyless run reporting to a local JSON Lines log file.
- `scfw/internal/verifier` defines the local package verification framework: the `Verifier` interface that concrete verifiers implement. Subpackages `verifier/osv` (OSV.dev advisories), `verifier/ddmalware` (Datadog malicious-software-packages-dataset), `verifier/age` (recently-published packages), and `verifier/list` (user-provided findings lists) each implement one verification source.
- `scfw/internal/home` resolves SCFW's home directory (`SCFW_HOME`, else a directory under the user's cache directory), where verification data is cached and the local log is written.
- `scfw/internal/ecosystem` owns registry/ecosystem operations that are independent of a particular package-manager executable, such as resolving npm or PyPI publication data.
- `scfw/internal/git` discovers local Git repository metadata and removes credentials before reporting.
- `scfw/internal/pm` owns the shared package and package-manager abstractions, version handling, and reusable collections. Keep this package independent of concrete package managers.
- `scfw/internal/pm/npm`, `scfw/internal/pm/pip`, and `scfw/internal/pm/poetry` each own integration with that executable: supported commands and versions, dry-run or temporary-project behavior, output parsing, and conversion into the shared `pm.Package` model.
- Tests live beside the code they cover as `*_test.go` files. Add or update focused tests with every behavioral change.
- `.goreleaser.yml` is the authoritative cross-platform release-build configuration. Root-level files such as `go.mod`, `go.sum`, `Makefile`, and `.golangci.yml` define dependencies and development tooling.
- `.github` contains CI, release, and repository automation; `images` contains documentation assets.

## Structure maintenance rule

Keep this guide accurate as part of every structural change. In the same change that creates, removes, renames, moves, or materially repurposes a package or top-level directory, update the structure section above to state its responsibility and boundaries. A new package must have one clear, cohesive responsibility, live at the narrowest appropriate scope, and avoid duplicating responsibilities already assigned here. If its purpose cannot be described in one concise sentence, reconsider the package boundary before adding it.

Preserve the existing separation of concerns: the CLI orchestrates, `ddapi` communicates with Datadog, `ecosystem` communicates with registries, `pm` provides shared domain abstractions, and each `pm/<manager>` package implements one package-manager adapter. Do not put manager-specific parsing in `pm`, API transport in `cli`, or CLI presentation in lower-level packages.

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
