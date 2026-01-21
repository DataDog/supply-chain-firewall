# Supply-Chain Firewall subcommands

## `scfw audit`

The `audit` subcommand is used to verify all currently installed packages managed by a given supported package manager.

Supply-Chain Firewall audits all installed packages visible to the package manager in the invoking environment.  The user may specify the package manager executable they wish to use on the command line.  For `npm` and `poetry` audits, Supply-Chain Firewall assumes the project of interest is in the current working directory.

Currently, `npm` audits do not take globally installed packages into consideration.  To audit a globally installed `npm` package, first `cd` into the package's directory (inside the global `node_modules/`) and perform a local audit there.

```bash
$ scfw audit --help
usage: scfw audit [-h] [--executable PATH] {npm,pip,poetry}

Audit installed packages using Supply-Chain Firewall's verifiers.

positional arguments:
  {npm,pip,poetry}   The package manager whose installed packages should be verified

options:
  -h, --help         show this help message and exit
  --executable PATH  Package manager executable to use for running commands (default: environmentally determined)
```

## `scfw configure`

The `configure` subcommand may be used to configure the environment with shell aliases and environment variables in order to get the most out of Supply-Chain Firewall.  It may be run repeatedly to update desired configuration settings.

Selected configuration options are written to the user's pre-existing `~/.bashrc` and `~/.zshrc` files in a clearly delimited block that Supply-Chain Firewall manages.  This block should never be manually edited, at the risk of breaking SCFW's ability to maintain these files and its own options successfully.

When run with no command-line arguments, the `configure` subcommand launches an interactive configurator that walks the user through the available set of supported options.  Otherwise, it may be run non-interactively by passing the desired options on the command line.

The `--remove` option may be used to remove all saved SCFW-managed configuration options.  It may not be passed with any other command-line option.

```bash
usage: scfw configure [-h] [-r] [--alias-npm] [--alias-pip] [--alias-poetry] [--dd-agent-port PORT] [--dd-api-key KEY] [--dd-log-level LEVEL] [--scfw-home PATH]

Configure the environment for using Supply-Chain Firewall.

options:
  -h, --help            show this help message and exit
  -r, --remove          Remove all Supply-Chain Firewall-managed configuration
  --alias-npm           Add shell aliases to always run npm commands through Supply-Chain Firewall
  --alias-pip           Add shell aliases to always run pip commands through Supply-Chain Firewall
  --alias-poetry        Add shell aliases to always run Poetry commands through Supply-Chain Firewall
  --dd-agent-port PORT  Configure log forwarding to the local Datadog Agent on the given port
  --dd-api-key KEY      API key to use when forwarding logs via the Datadog API
  --dd-log-level LEVEL  Desired logging level for Datadog log forwarding (options: ALLOW, BLOCK)
  --scfw-home PATH      Directory that Supply-Chain Firewall can use as a local cache
```

## `scfw run`

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

Users may configure the behavior of this subcommand via the following environment variables:

* `SCFW_ON_WARNING`:
  Takes the values `ALLOW` or `BLOCK` and has the same effect as passing the command-line options `--allow-on-warning` or `--block-on-warning`, respectively.

  The command-line options take precedence over this environment variable in cases where both are set.
