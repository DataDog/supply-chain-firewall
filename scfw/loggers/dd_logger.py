"""
Provides a `FirewallLogger` class for sending logs to Datadog.
"""

import getpass
import json
import logging
import os
from pathlib import Path
import socket
from typing import Any, Iterable, Optional

import dotenv

import scfw
from scfw.constants import DD_ENV, DD_LOG_LEVEL_VAR, DD_SERVICE, DD_SOURCE, SCFW_HOME_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger, FirewallRunSummary
from scfw.package import Package
from scfw.report import FindingsReport, UnverifiablePackageReport, VerificationReport
from scfw.verifier import FindingSeverity

_log = logging.getLogger(__name__)

# The `created` and `msg` attributes are provided by `logging.LogRecord`
_AUDIT_ATTRIBUTES = {
    "audited_packages",
    "created",
    "ecosystem",
    "findings",
    "executable",
    "msg",
    "package_manager",
    "unverifiable",
}
_FIREWALL_ACTION_ATTRIBUTES = {
    "action",
    "created",
    "ecosystem",
    "executable",
    "installed_packages",
    "msg",
    "package_manager",
    "relevant_findings",
    "unverifiable",
    "verified",
    "warned",
}

_ALL_LOG_ATTRIBUTES = _AUDIT_ATTRIBUTES | _FIREWALL_ACTION_ATTRIBUTES

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
            "cwd": os.getcwd(),
        }

        try:
            log_record["username"] = getpass.getuser()
        except Exception as e:
            _log.warning(f"Failed to query username while formatting log: {e}")

        for key in _ALL_LOG_ATTRIBUTES:
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
            _log.warning(f"Invalid value for {DD_LOG_LEVEL_VAR}: using default level {_DD_LOG_LEVEL_DEFAULT}")

    def log_firewall_run(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        run_summary: FirewallRunSummary,
    ):
        """
        Log the data and action taken in a completed run of Supply-Chain Firewall.

        Args:
            ecosystem: The ecosystem of the inspected package manager command.
            package_manager: The command-line name of the package manager.
            executable: The executable used to execute the inspected package manager command.
            run_summary: The summary of the completed run of Supply-Chain Firewall to be logged.
        """
        if run_summary.action < self._level:
            return

        log_data = {
            "ecosystem": str(ecosystem),
            "package_manager": package_manager,
            "executable": executable,
            "action": str(run_summary.action),
            "verified": run_summary.report is not None,
            "warned": run_summary.warned,
        }

        if run_summary.action == FirewallAction.ALLOW and run_summary.install_targets:
            log_data["installed_packages"] = _format_packages(run_summary.install_targets)

        if run_summary.relevant_findings:
            log_data["relevant_findings"] = _format_findings(run_summary.relevant_findings)

        if run_summary.report is not None and (unverifiable := run_summary.report.get_unverifiable()):
            log_data["unverifiable"] = _format_unverifiable(unverifiable)

        self._logger.info(
            f"Command '{' '.join(run_summary.command)}' was {str(run_summary.action).lower()}ed",
            extra=log_data,
        )

    def log_audit(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        report: VerificationReport,
    ):
        """
        Log the results of an audit for the given ecosystem and package manager.

        Args:
            ecosystem: The ecosystem of the audited packages.
            package_manager: The package manager that manages the audited packages.
            executable: The package manager executable used to enumerate audited packages.
            report: The report containing the verification results for the audited packages.
        """
        self._logger.info(
            f"Successfully audited {ecosystem} packages managed by {package_manager}",
            extra={
                "ecosystem": str(ecosystem),
                "package_manager": package_manager,
                "executable": executable,
                "audited_packages": _format_packages(report.packages()),
                "findings": [
                    formatted
                    for severity in FindingSeverity
                    for formatted in _format_findings(report.get_findings(severity))
                ],
                "unverifiable": _format_unverifiable(report.get_unverifiable()),
            }
        )


def _format_packages(packages: Iterable[Package]) -> list[dict[str, Optional[str]]]:
    """
    Format a set of `Package` for logging as JSON.
    """
    return list(map(lambda package: package.to_dict(), sorted(packages, key=str)))


def _format_findings(
    findings: FindingsReport,
) -> list[dict[str, str | dict[str, Optional[str]]]]:
    """
    Format a set of findings for logging as JSON.
    """
    return [
        {
            "package": package.to_dict(),
            "verifier": finding.verifier,
            "severity": str(finding.severity),
            "finding": finding.finding,
        }
        for package, findings in findings.items()
        for finding in sorted(findings, key=lambda f: f.severity)
    ]


def _format_unverifiable(
    unverifiable: UnverifiablePackageReport,
) -> list[dict[str, dict[str, Optional[str]] | list[dict[str, str]]]]:
    """
    Format a set of unverifiable package error messages for logging as JSON.
    """
    return [
        {
            "package": package.to_dict(),
            "error_messages": [
                {
                    "verifier": error_message.verifier,
                    "error_message": error_message.error_message,
                }
                for error_message in sorted(error_messages, key=lambda e: e.verifier)
            ]
        }
        for package, error_messages in unverifiable.items()
    ]
