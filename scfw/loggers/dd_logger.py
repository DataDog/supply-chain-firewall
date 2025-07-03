"""
Provides a `FirewallLogger` class for sending logs to Datadog.
"""

import getpass
import json
import logging
import os
import socket

import dotenv

import scfw
from scfw.configure import DD_ENV, DD_LOG_LEVEL_VAR, DD_SERVICE, DD_SOURCE
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger
from scfw.package import Package
from scfw.report import VerificationReport
from scfw.verifier import FindingSeverity

_log = logging.getLogger(__name__)

_DD_LOG_LEVEL_DEFAULT = FirewallAction.BLOCK

# The `created` and `msg` attributes are provided by `logging.LogRecord`
_AUDIT_ATTRIBUTES = {
    "created",
    "ecosystem",
    "executable",
    "msg",
    "package_manager",
    "reports"
}
_FIREWALL_ACTION_ATTRIBUTES = {
    "action",
    "created",
    "ecosystem",
    "executable",
    "msg",
    "package_manager",
    "targets",
    "warned"
}


dotenv.load_dotenv()


class DDLogFormatter(logging.Formatter):
    """
    A custom JSON formatter for firewall logs.
    """
    def format(self, record) -> str:
        """
        Format a log record as a JSON string.

        Args:
            record: The log record to be formatted.
        """
        log_record = {
            "source": DD_SOURCE,
            "service": DD_SERVICE,
            "version": scfw.__version__,
            "env": os.getenv("DD_ENV", DD_ENV),
            "hostname": socket.gethostname(),
        }

        try:
            log_record["username"] = getpass.getuser()
        except Exception as e:
            _log.warning(f"Failed to query username: {e}")

        for key in _AUDIT_ATTRIBUTES | _FIREWALL_ACTION_ATTRIBUTES:
            if (value := record.__dict__.get(key)):
                log_record[key] = value

        return json.dumps(log_record) + '\n'


class DDLogger(FirewallLogger):
    """
    An implementation of `FirewallLogger` for sending logs to Datadog.
    """
    def __init__(self, logger: logging.Logger):
        """
        Initialize a new `DDLogger`.

        Args:
            logger: A configured log handle to which logs will be written.
        """
        self._logger = logger
        self._level = _DD_LOG_LEVEL_DEFAULT

        try:
            if (dd_log_level := os.getenv(DD_LOG_LEVEL_VAR)) is not None:
                self._level = FirewallAction.from_string(dd_log_level)
        except ValueError:
            _log.warning(f"Undefined or invalid Datadog log level: using default level {_DD_LOG_LEVEL_DEFAULT}")

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
        Log the data and action taken in a completed run of Supply-Chain Firewall.

        Args:
            ecosystem: The ecosystem of the inspected package manager command.
            package_manager: The command-line name of the package manager.
            executable: The executable used to execute the inspected package manager command.
            command: The package manager command line provided to the firewall.
            targets: The installation targets relevant to firewall's action.
            action: The action taken by the firewall.
            warned: Indicates whether the user was warned about findings and prompted for approval.
        """
        if not self._level or action < self._level:
            return

        self._logger.info(
            f"Command '{' '.join(command)}' was {str(action).lower()}ed",
            extra={
                "ecosystem": str(ecosystem),
                "package_manager": package_manager,
                "executable": executable,
                "targets": list(map(str, targets)),
                "action": str(action),
                "warned": warned,
            }
        )

    def log_audit(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        reports: dict[FindingSeverity, VerificationReport]
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
