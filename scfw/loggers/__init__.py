"""
Exposes the currently discoverable set of client loggers implementing SCFW's
logging protocol.

Firewall users may provide custom loggers according to their own logging needs.
SCFW discovers loggers at runtime via the following simple protocol. The module
implementing the custom logger must contain a function with the following name
and signature:

```
def load_logger() -> FirewallLogger
```

This `load_logger` function should return an instance of the custom logger
for SCFW's use. The module may then be placed in the same directory as this
source file for runtime import. Make sure to reinstall the `scfw` package after
doing so.
"""

import importlib
import logging
import os
import pkgutil

from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallLogger, FirewallRunSummary
from scfw.report import VerificationReport

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
                _log.debug(f"Module {module} does not export a logger")
            except Exception as e:
                _log.warning(f"Failed to initialize logger defined in {module}: {e}")

        if not self._loggers:
            _log.warning("No loggers were discovered and successfully initialized")

    def log_firewall_run(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        run_summary: FirewallRunSummary,
    ):
        """
        Log the data and action taken in a completed run of Supply-Chain Firewall to
        all client loggers.
        """
        for logger in self._loggers:
            try:
                logger.log_firewall_run(
                    ecosystem,
                    package_manager,
                    executable,
                    run_summary,
                )
            except Exception as e:
                _log.warning(f"Failed to log firewall run: {e}")

    def log_audit(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        report: VerificationReport,
    ):
        """
        Log the results of an audit to all client loggers.
        """
        for logger in self._loggers:
            try:
                logger.log_audit(ecosystem, package_manager, executable, report)
            except Exception as e:
                _log.warning(f"Failed to log audit: {e}")
