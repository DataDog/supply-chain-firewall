# Local policy and noninteractive decisions

The `local-policy` suite discovers an old public npm or PyPI package, installs its exact version through the release-built SCFW binary, and independently observes installed state. The same registered recipes run on each selected manager/version cell: npm, pip and Poetry in resolution/proxy modes, and uv in proxy mode.

The suite covers CRITICAL/WARNING lists, exact/mismatched/all/wildcard versions, severity and ecosystem case handling, both YAML filename extensions, multiple files, malformed YAML and invalid severity. Warning cases exercise flags, environment precedence and the default non-TTY decision; explicit BLOCK remains effective when warnings are allowed. Report-failure cases use a regular file as the requested log directory, so the failure is deterministic even for privileged runners. Policy is marked NOT_OBSERVED when the report cannot be written; command and installation observations still verify the decision.

Use the inputs documented in `e2e/README.md`, adding `local-policy` to the selected cell's suites and setting `SCFW_E2E_SUITES=local-policy`. Run `TestPlan`, `TestDiscover`, then `TestE2E` with `-tags=e2e`. Public verifier services remain enabled. Case evidence retains finding files, policy records when available, project snapshots, exact commands, installed-state observations and cleanup checks.

The private-source complement belongs to controlled-registry tests. Interactive TTY behavior belongs to the terminal suite. These cases make no claim about those paths.
