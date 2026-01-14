# `scfw run`

The `run` subcommand is used to run a package manager command through Supply-Chain Firewall while verifying installation targets.

All package targets that would be installed by running the given package manager command are verified against the set of verifiers that SCFW was able to discover at the time of invocation.  The command is automatically blocked from running when any verifier returns critical findings for any target, generally indicating that the target in question is malicious.  In cases where a verifier reports warnings for a target, they are presented to the user along with a prompt confirming intent to proceed with the installation.  Otherwise, the command is allowed to run as if SCFW were not present.

For `pip install` commands, packages will be installed in the same environment (virtual or global) in which the command was run.

```bash
$ scfw run --help
usage: scfw run [options] COMMAND

Run a package manager command through Supply-Chain Firewall.

options:
  -h, --help           show this help message and exit
  --dry-run            Verify any installation targets but do not run the package manager command
  --allow-on-warning   Non-interactively allow commands with only warning-level findings
  --allow-unsupported  Disable verification and allow commands for unsupported package manager versions
  --block-on-warning   Non-interactively block commands with only warning-level findings
  --error-on-block     Treat blocked commands as errors (useful for scripting)
  --executable PATH    Package manager executable to use for running commands (default: environmentally determined)
```
