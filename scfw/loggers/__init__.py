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
from scfw.package import Package
from scfw.report import VerificationReport
from scfw.verifier import FindingSeverity

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

    def log_firewall_action(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        command: list[str],
        targets: list[Package],
        action: FirewallAction,
        warned: bool
    ):
        """
        Log the data and action taken in a completed run of Supply-Chain Firewall to
        all client loggers.
        """
        for logger in self._loggers:
            logger.log_firewall_action(ecosystem, package_manager, executable, command, targets, action, warned)

    def log_audit(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        reports: dict[FindingSeverity, VerificationReport]
    ):
        """
        Log the results of an audit to all client loggers.
        """
        for logger in self._loggers:
            logger.log_audit(ecosystem, package_manager, executable, reports)
