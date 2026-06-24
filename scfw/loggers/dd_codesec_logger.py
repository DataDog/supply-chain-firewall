"""
Provides a `FirewallLogger` for Datadog Code Security's Supply Chain Firewall API.
"""

import logging
import os
import socket
from typing import Any
import uuid

import requests

from scfw.constants import DD_API_KEY_VAR, DD_APP_KEY_VAR, DD_SITE_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger, FirewallRunSummary
from scfw.report import Finding, VerificationReport

_log = logging.getLogger(__name__)

_CODESEC_LOGGER_API_ENDPOINT = "api/v2/static-analysis-sca/scfw/report"

DD_CODESEC_LOGGER_ENABLED_VAR = "SCFW_DD_CODESEC_LOGGER_ENABLED"
"""
Setting this environment variable is required to enable the Datadog Code Security logger.
"""


class DDCodeSecurityLogger(FirewallLogger):
    """
    An implementation of `FirewallLogger` for sending logs to Datadog Code Security's
    Supply Chain Firewall API.
    """
    def __init__(self):
        """
        Initialize a new `DDCodeSecurityLogger`.
        """
        self._enabled = bool(os.getenv(DD_CODESEC_LOGGER_ENABLED_VAR))

    def log_firewall_run(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        run_summary: FirewallRunSummary,
    ):
        """
        Log the data and action taken in a completed run of Supply Chain Firewall.

        Args:
            ecosystem: The ecosystem of the inspected package manager command.
            package_manager: The command-line name of the package manager.
            executable: The executable used to execute the inspected package manager command.
            run_summary: The summary of the completed run of Supply Chain Firewall to be logged.
        """
        if not self._enabled:
            return

        dd_api_key = os.getenv(DD_API_KEY_VAR)
        dd_app_key = os.getenv(DD_APP_KEY_VAR)
        if not (dd_api_key and dd_app_key):
            raise RuntimeError("Missing required Datadog API key or application key")

        dd_site = os.getenv(DD_SITE_VAR, "datadoghq.com")

        try:
            r = requests.post(
                f"https://api.{dd_site}/{_CODESEC_LOGGER_API_ENDPOINT}",
                headers={
                    "dd-api-key": dd_api_key,
                    "dd-application-key": dd_app_key,
                },
                json=self.generate_api_payload(package_manager, executable, run_summary),
                timeout=10,
            )
            r.raise_for_status()

        except Exception as e:
            raise RuntimeError(f"Code Security API request failed: {e}")

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
        if not self._enabled:
            return

        _log.warning("`log_audit` is not currently implemented for the Code Security API")

    def generate_api_payload(
        self,
        package_manager: str,
        executable: str,
        run_summary: FirewallRunSummary,
    ) -> dict:
        """
        Generate the API payload from the `log_firewall_run()` inputs.

        Args:
            package_manager: The command-line name of the package manager.
            executable: The executable used to execute the inspected package manager command.
            run_summary: The summary of the completed run of Supply Chain Firewall to be logged.

        Returns:
            A `dict` containing the API's JSON payload generated from the inputs.
        """
        def get_reports(run_summary: FirewallRunSummary) -> list[dict]:
            reports = []

            match run_summary.action:
                case FirewallAction.ALLOW:
                    reported_packages = run_summary.install_targets or set()
                case FirewallAction.BLOCK:
                    # When the action is BLOCK due solely to unverifiable packages,
                    # relevant_findings is None and reports will be empty.
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
            "executable": executable,
            "hostname": socket.gethostname(),
            "package_manager": package_manager,
        }

        attributes["command"] = ' '.join(run_summary.command)
        attributes["outcome"] = str(run_summary.action)

        attributes["reports"] = get_reports(run_summary)

        return {
            "data": {
                "type": "scfw-report-request",
                "id": str(uuid.uuid4()),
                "attributes": attributes,
            }
        }


def load_logger() -> FirewallLogger:
    """
    Export `DDCodeSecurityLogger` for discovery by Supply Chain Firewall.

    Returns:
        A `DDCodeSecurityLogger` for use in a run of Supply Chain Firewall.
    """
    return DDCodeSecurityLogger()
