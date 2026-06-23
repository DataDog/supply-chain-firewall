"""
Provides a `FirewallLogger` for Datadog Code Security's Supply-Chain Firewall API.
"""

import json
import logging
import os
import socket
from typing import Any, Type
import uuid

import requests

from scfw.constants import DD_API_KEY_VAR, DD_APP_KEY_VAR, DD_SITE_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger, FirewallRunSummary
from scfw.report import Finding, VerificationReport

_log = logging.getLogger(__name__)

_DD_LOG_NAME = "dd_codesec_log"

_CODESEC_LOGGER_API_ENDPOINT = "api/v2/static-analysis-sca/scfw/report"

DD_CODESEC_LOGGER_ENABLED_VAR = "SCFW_DD_CODESEC_LOGGER_ENABLED"
"""
Setting this environment variable is required to enable the Datadog Code Security logger.
"""


class _DDCodeSecurityLogFormatter(logging.Formatter):
    """
    A custom log formatter for Datadog Code Security's Supply-Chain Firewall API.
    """
    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record as JSON in the API's expected format.

        Args:
            record: The log record to be formatted.

        Returns:
            A `str` containing the formatted log record.
        """
        def get_or_raise(d: dict, key: str, typ: Type) -> Any:
            if key not in d:
                raise ValueError(f"Missing required key: '{key}'")

            value = d[key]
            if not isinstance(value, typ):
                raise TypeError(f"Incompatible type for '{key}' value: require {typ}")

            return value

        def get_reports(run_summary: FirewallRunSummary) -> list[dict]:
            reports = []

            match run_summary.action:
                case FirewallAction.ALLOW:
                    reported_packages = run_summary.install_targets or set()
                case FirewallAction.BLOCK:
                    reported_packages = set(run_summary.relevant_findings or {})

            for package in reported_packages:
                findings: set[Finding] = set()
                if run_summary.relevant_findings:
                    findings = run_summary.relevant_findings.get(package, set())

                report = {
                    "ecosystem": str(package.ecosystem),
                    "package": package.name,
                    "version": package.version,
                    "warning": run_summary.warning and len(findings) != 0,
                    "findings": [
                        {
                            "verifier": finding.verifier,
                            "finding": finding.finding,
                        }
                        for finding in findings
                    ]
                }
                reports.append(report)

            return reports

        attributes: dict[str, Any] = {
            "cwd": os.getcwd(),
            "hostname": socket.gethostname(),
        }

        attributes["package_manager"] = get_or_raise(record.__dict__, "package_manager", str)
        attributes["executable"] = get_or_raise(record.__dict__, "executable", str)

        run_summary: FirewallRunSummary = get_or_raise(record.__dict__, "run_summary", FirewallRunSummary)
        attributes["command"] = ' '.join(run_summary.command)
        attributes["outcome"] = str(run_summary.action)

        attributes["reports"] = get_reports(run_summary)

        return json.dumps(
            {
                "data": {
                    "type": "scfw-report-request",
                    "id": str(uuid.uuid4()),
                    "attributes": attributes,
                }
            }
        )


class _DDCodeSecurityLogHandler(logging.Handler):
    """
    A custom log handler for Datadog Code Security's Supply-Chain Firewall API.
    """
    def emit(self, record: logging.LogRecord):
        """
        Format and send a log to the Code Security Supply-Chain Firewall API.

        Args:
            record: The log record to be forwarded.

        Raises:
            RuntimeError:
                * Missing required Datadog API key or application key
                * Code Security API request failed (includes reason)
        """
        dd_api_key = os.getenv(DD_API_KEY_VAR)
        dd_app_key = os.getenv(DD_APP_KEY_VAR)
        if not (dd_api_key and dd_app_key):
            raise RuntimeError("Missing required Datadog API key or application key")

        dd_site = os.getenv(DD_SITE_VAR, "datadoghq.com")

        try:
            r = requests.post(
                f"https://api.{dd_site}/{_CODESEC_LOGGER_API_ENDPOINT}",
                headers={
                    "DD-API-KEY": dd_api_key,
                    "dd-application-key": dd_app_key,
                },
                json=json.loads(self.format(record)),
            )
            r.raise_for_status()

        except Exception as e:
            raise RuntimeError(f"Code Security API request failed: {e}")


# Configure a single logging handle for all `DDCodeSecurityLogger` instances to share
_handler = _DDCodeSecurityLogHandler() if os.getenv(DD_CODESEC_LOGGER_ENABLED_VAR) else logging.NullHandler()
_handler.setFormatter(_DDCodeSecurityLogFormatter())

_ddlog = logging.getLogger(_DD_LOG_NAME)
_ddlog.setLevel(logging.INFO)
_ddlog.addHandler(_handler)


class DDCodeSecurityLogger(FirewallLogger):
    """
    An implementation of `FirewallLogger` for sending logs to Datadog Code Security's
    Supply-Chain Firewall API.
    """
    def __init__(self):
        """
        Initialize a new `DDCodeSecurityLogger`.
        """
        self._logger = _ddlog

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
        log_data = {
            "ecosystem": ecosystem,
            "package_manager": package_manager,
            "executable": executable,
            "run_summary": run_summary,
        }

        self._logger.info(msg=None, extra=log_data)

    def log_audit(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        report: VerificationReport,
    ):
        """
        Log the results of an audit for the given ecosystem and package manager.
        This function is not currently implemented: calling it will have no effect
        other than emitting a warning.

        Args:
            ecosystem: The ecosystem of the audited packages.
            package_manager: The package manager that manages the audited packages.
            executable: The package manager executable used to enumerate audited packages.
            report: The report containing the verification results for the audited packages.
        """
        if (
            len(self._logger.handlers) == 1
            and isinstance(self._logger.handlers[0], logging.NullHandler)
        ):
            return

        _log.warning("`log_audit` is not currently implemented for the Code Security API")


def load_logger() -> FirewallLogger:
    """
    Export `DDCodeSecurityLogger` for discovery by Supply-Chain Firewall.

    Returns:
        A `DDCodeSecurityLogger` for use in a run of Supply-Chain Firewall.
    """
    return DDCodeSecurityLogger()
