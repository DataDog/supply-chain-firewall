"""
Exposes the currently discoverable set of client loggers implementing the
firewall's logging protocol.

Two loggers ship with the supply chain firewall by default: `DDAgentLogger`
and `DDAPILogger`, which send logs to Datadog via a local Datadog Agent
or the HTTP API, respectively. Firewall users may additionally provide custom
loggers according to their own logging needs.

The firewall discovers loggers at runtime via the following simple protocol.
The module implementing the custom logger must contain a function with the
following name and signature:

```
def load_logger() -> FirewallLogger
```

This `load_logger` function should return an instance of the custom logger
for the firewall's use. The module may then be placed in the same directory
as this source file for runtime import. Make sure to reinstall the package
after doing so.
"""

import importlib
import logging
import os
import pkgutil

from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger
from scfw.target import InstallTarget

_log = logging.getLogger(__name__)


class FirewallLoggers(FirewallLogger):
    """
    A `FirewallLogger` that logs to all currently discoverable `FirewallLoggers`.
    """
    def __init__(self):
        """
        Initialize a new `FirewallLoggers` instance from currently discoverable loggers.
        """
        self._loggers = []

        for _, module, _ in pkgutil.iter_modules([os.path.dirname(__file__)]):
            try:
                logger = importlib.import_module(f".{module}", package=__name__).load_logger()
                self._loggers.append(logger)
            except ModuleNotFoundError:
                _log.warning(f"Failed to load module {module} while collecting loggers")
            except AttributeError:
                _log.info(f"Module {module} does not export a logger")

    def log(
        self,
        ecosystem: ECOSYSTEM,
        executable: str,
        command: list[str],
        targets: list[InstallTarget],
        action: FirewallAction,
        warned: bool
    ):
        """
        Log a completed run of the supply-chain firewall to all discovered loggers.
        """
        for logger in self._loggers:
            logger.log(ecosystem, executable, command, targets, action, warned)
