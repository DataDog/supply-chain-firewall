"""
Provides a `FirewallLogger` class for sending logs to Datadog.
"""

import getpass
import json
import logging
import os
from pathlib import Path
import socket
from typing import Any

import dotenv

import scfw
from scfw.constants import DD_ENV, DD_LOG_LEVEL_VAR, DD_SERVICE, DD_SOURCE, SCFW_HOME_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger
from scfw.package import Package
from scfw.report import VerificationReport
from scfw.verifier import FindingSeverity

_log = logging.getLogger(__name__)

# The `created` and `msg` attributes are provided by `logging.LogRecord`
_AUDIT_ATTRIBUTES = {
    "created",
    "ecosystem",
    "executable",
    "msg",
    "package_manager",
    "reports",
}
_FIREWALL_ACTION_ATTRIBUTES = {
    "action",
    "created",
    "ecosystem",
    "executable",
    "msg",
    "package_manager",
    "targets",
    "verified",
    "warned",
}

_DD_LOG_LEVEL_DEFAULT = FirewallAction.BLOCK

DD_LOGGER_HOME = Path("dd_logger/")
"""
The Datadog logger home directory, realtive to `SCFW_HOME`.
"""

DD_LOG_ATTRIBUTES_FILE_DEFAULT = DD_LOGGER_HOME / "log_attributes.json"
"""
The default filepath where the Datadog logger looks for a custom log attributes file.
"""

DD_LOG_ATTRIBUTES_FILE_VAR = "SCFW_DD_LOG_ATTRIBUTES_FILE"
"""
The environment variable under which the Datadog logger looks for a filepath to a
custom log attributes file.
"""

DD_LOG_ATTRIBUTES_VAR = "SCFW_DD_LOG_ATTRIBUTES"
"""
The environment variable under which the Datadog logger looks for JSON containing
custom log attributes.
"""


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
        def parse_log_attributes(json_str: str) -> dict[str, Any]:
            attributes = json.loads(json_str)
            if not isinstance(attributes, dict):
                raise RuntimeError("Custom Datadog log attributes must be structured as a single JSON object")

            return attributes

        def read_log_attributes_env() -> dict[str, Any]:
            attributes_json = os.getenv(DD_LOG_ATTRIBUTES_VAR)
            if not attributes_json:
                return {}

            attributes = parse_log_attributes(attributes_json)

            _log.info("Read custom Datadog log attributes from the environment")
            return attributes

        def read_log_attributes_file() -> dict[str, Any]:
            file_var, attributes_file = None, None
            if (file_var := os.getenv(DD_LOG_ATTRIBUTES_FILE_VAR)):
                attributes_file = Path(file_var)
            elif (home_dir := os.getenv(SCFW_HOME_VAR)):
                attributes_file = Path(home_dir) / DD_LOG_ATTRIBUTES_FILE_DEFAULT

            if not (attributes_file and attributes_file.is_file()):
                if file_var:
                    raise RuntimeError(
                        f"Custom Datadog log attributes file {attributes_file} does not exist or is not a regular file"
                    )
                return {}

            with open(attributes_file) as f:
                attributes = parse_log_attributes(f.read())

            _log.info(f"Read custom Datadog log attributes from file {attributes_file}")
            return attributes

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
            _log.warning(f"Failed to query username while formatting log: {e}")

        for key in _AUDIT_ATTRIBUTES | _FIREWALL_ACTION_ATTRIBUTES:
            try:
                log_record[key] = record.__dict__[key]
            except KeyError:
                pass

        # Read custom log attributes from the environment, if any
        try:
            for attribute, value in read_log_attributes_env().items():
                log_record.setdefault(attribute, value)
        except Exception as e:
            _log.warning(f"Failed to read custom Datadog log attributes from the environment: {e}")

        # Read custom log attributes from file, if any
        try:
            for attribute, value in read_log_attributes_file().items():
                log_record.setdefault(attribute, value)
        except Exception as e:
            _log.warning(f"Failed to read custom Datadog log attributes from file: {e}")

        return json.dumps(log_record)


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
