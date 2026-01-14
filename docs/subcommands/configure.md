# `scfw configure`

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
