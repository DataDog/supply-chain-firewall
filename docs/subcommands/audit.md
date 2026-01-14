# `scfw audit`

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
