"""
Lorem ipsum dolor sit amet.
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
Lorem ipsum dolor sit amet.
"""


class _DDCodeSecurityLogFormatter(logging.Formatter):
    """
    Lorem ipsum dolor sit amet.
    """
    def format(self, record: logging.LogRecord) -> str:
        """
        Lorem ipsum dolor sit amet.
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
    Lorem ipsum dolor sit amet.
    """
    def emit(self, record: logging.LogRecord):
        """
        Lorem ipsum dolor sit amet.
        """
        dd_api_key = os.getenv(DD_API_KEY_VAR)
        dd_app_key = os.getenv(DD_APP_KEY_VAR)
        if not (dd_api_key and dd_app_key):
            _log.warning("Lorem ipsum dolor sit amet")
            return

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
            _log.warning(f"Lorem ipsum dolor sit amet: {e}")


# Lorem ipsum dolor sit amet
_handler = _DDCodeSecurityLogHandler() if os.getenv(DD_CODESEC_LOGGER_ENABLED_VAR) else logging.NullHandler()
_handler.setFormatter(_DDCodeSecurityLogFormatter())

_ddlog = logging.getLogger(_DD_LOG_NAME)
_ddlog.setLevel(logging.INFO)
_ddlog.addHandler(_handler)


class DDCodeSecurityLogger(FirewallLogger):
    """
    Lorem ipsum dolor sit amet.
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
        Lorem ipsum dolor sit amet.
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
        Lorem ipsum dolor sit amet.
        """
        if (
            len(self._logger.handlers) == 1
            and isinstance(self._logger.handlers[0], logging.NullHandler)
        ):
            return

        _log.warning("Lorem ipsum dolor sit amet")


def load_logger() -> FirewallLogger:
    """
    Export `DDCodeSecurityLogger` for discovery by Supply-Chain Firewall.

    Returns:
        A `DDCodeSecurityLogger` for use in a run of Supply-Chain Firewall.
    """
    return DDCodeSecurityLogger()
