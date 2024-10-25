"""
Users of the supply chain firewall are able to use their own custom
loggers according to their own logging needs.  This module contains a
template for writing such a custom logger.

The firewall discovers loggers at runtime via the following simple protocol.
The module implementing the custom logger must contain a function with the
following name and signature:

```
def load_logger() -> FirewallLogger
```

This `load_logger` function should return an instance of the custom logger
for the firewall's use. The module may then be placed in the `scfw/loggers`
directory for runtime import, no further modification required. Make sure
to reinstall the package after doing so.
"""

from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger
from scfw.target import InstallTarget


class CustomFirewallLogger(FirewallLogger):
    def log(
        self,
        action: FirewallAction,
        ecosystem: ECOSYSTEM,
        command: list[str],
        targets: list[InstallTarget]
    ):
        return


def load_logger() -> FirewallLogger:
    return CustomFirewallLogger()
