"""
Provides a `FirewallLogger` class for writing a local JSON Lines log file.
"""

import logging
import os
from pathlib import Path

from scfw.constants import SCFW_HOME_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FindingSeverity, FirewallAction, FirewallLogger
from scfw.loggers.dd_logger import DDLogFormatter
from scfw.package import Package
from scfw.report import VerificationReport

_log = logging.getLogger(__name__)

LOG_FILE_NAME = "scfw.log"
"""
The default local log file within `SCFW_HOME`.
"""

LOG_FILE_VAR = "SCFW_LOG_FILE"
"""
The environment variable under which the local file logger looks for a log file
to write to instead of using the default file.
"""


# Configure a single logging handle for all `FileLogger` instances to share
_handler = logging.NullHandler()
if (log_file := os.getenv(LOG_FILE_VAR)):
    _handler = logging.FileHandler(log_file)
elif (scfw_home := os.getenv(SCFW_HOME_VAR)):
    _handler = logging.FileHandler(Path(scfw_home) / LOG_FILE_NAME)
else:
    _log.warning(
        f"No local log file configured: consider setting {LOG_FILE_VAR} or {SCFW_HOME_VAR}"
    )
_handler.setFormatter(DDLogFormatter())

_file_log = logging.getLogger("file_logger")
_file_log.setLevel(logging.INFO)
_file_log.addHandler(_handler)


class FileLogger(FirewallLogger):
    """
    An implementation of `FirewallLogger` for writing a local JSON lines log file.
    """
    def __init__(self):
        """
        Initialize a new `FileLogger`.
        """
        self._logger = _file_log

    def log_firewall_action(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        command: list[str],
        targets: list[Package],
        action: FirewallAction,
        verified: bool,
        warned: bool,
    ):
        """
        Log the data and action taken in a completed run of Supply-Chain Firewall.

        Args:
            ecosystem: The ecosystem of the inspected package manager command.
            package_manager: The command-line name of the package manager.
            executable: The executable used to execute the inspected package manager command.
            command: The package manager command line provided to the firewall.
            targets: The installation targets relevant to firewall's action.
            action: The action taken by the firewall.
            verified: Indicates whether verification was performed in taking the specified `action`.
            warned: Indicates whether the user was warned about findings and prompted for approval.
        """
        self._logger.info(
            f"Command '{' '.join(command)}' was {str(action).lower()}ed",
            extra={
                "ecosystem": str(ecosystem),
                "package_manager": package_manager,
                "executable": executable,
                "targets": list(map(str, targets)),
                "action": str(action),
                "verified": verified,
                "warned": warned,
            }
        )

    def log_audit(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        reports: dict[FindingSeverity, VerificationReport],
    ):
        """
        Log the results of an audit for the given ecosystem and package manager.

        Args:
            ecosystem: The ecosystem of the audited packages.
            package_manager: The package manager that manages the audited packages.
            executable: The package manager executable used to enumerate audited packages.
            reports: The severity-ranked reports resulting from auditing the installed packages.
        """
        self._logger.info(
            f"Successfully audited {ecosystem} packages managed by {package_manager}",
            extra={
                "ecosystem": str(ecosystem),
                "package_manager": package_manager,
                "executable": executable,
                "reports": {
                    str(severity): list(map(str, report.packages())) for severity, report in reports.items()
                },
            }
        )


def load_logger() -> FirewallLogger:
    """
    Export `FileLogger` for discovery by Supply-Chain Firewall.

    Returns:
        A `FileLogger` for use in a run of Supply-Chain Firewall.
    """
    return FileLogger()
