"""
Tests of the Datadog Code Security API logger.
"""

from dataclasses import replace
from datetime import datetime, timezone

from scfw.ecosystem import ECOSYSTEM
from scfw.loggers.dd_codesec_logger import DDCodeSecurityLogger
from scfw.logger import FirewallAction, FirewallRunSummary
from scfw.verifier import Finding, FindingSeverity

from tests.utils import build_registry_package

_PKG_A = build_registry_package(ECOSYSTEM.PyPI, "requests", "2.31.0")
_PKG_B = build_registry_package(ECOSYSTEM.PyPI, "numpy", "1.24.0")

_CRITICAL_FINDING = Finding("foo", FindingSeverity.CRITICAL, "critical finding")

_TIMESTAMP = datetime(2026, 7, 17, 12, 0, 0, tzinfo=timezone.utc)

_BASE_RUN_SUMMARY = FirewallRunSummary(
    timestamp=_TIMESTAMP,
    command=["pip", "install", "requests"],
    install_targets={_PKG_A},
    report=None,
    relevant_findings=None,
    warning=False,
    action=FirewallAction.ALLOW,
)


def _run_summary(**overrides) -> FirewallRunSummary:
    return replace(_BASE_RUN_SUMMARY, **overrides)


def test_payload_reports_install_timestamp():
    """
    The generated payload reports the run summary's timestamp as install_timestamp,
    formatted as an ISO 8601 string.
    """
    payload = DDCodeSecurityLogger().generate_api_payload("pip", "/usr/bin/pip", _run_summary())

    assert payload["data"]["attributes"]["install_timestamp"] == _TIMESTAMP.isoformat()


def test_payload_on_allow_reports_all_install_targets():
    """
    On an ALLOW action, the payload reports one entry per install target, with an
    empty findings list for clean packages.
    """
    summary = _run_summary(action=FirewallAction.ALLOW, install_targets={_PKG_A, _PKG_B})

    payload = DDCodeSecurityLogger().generate_api_payload("pip", "/usr/bin/pip", summary)
    reports = payload["data"]["attributes"]["reports"]

    assert {report["package"] for report in reports} == {_PKG_A.name, _PKG_B.name}
    assert all(report["findings"] == [] for report in reports)


def test_payload_on_block_reports_only_relevant_findings():
    """
    On a BLOCK action, the payload reports only the packages present in relevant_findings,
    along with their findings.
    """
    summary = _run_summary(
        action=FirewallAction.BLOCK,
        install_targets={_PKG_A, _PKG_B},
        relevant_findings={_PKG_A: {_CRITICAL_FINDING}},
    )

    payload = DDCodeSecurityLogger().generate_api_payload("pip", "/usr/bin/pip", summary)
    reports = payload["data"]["attributes"]["reports"]

    assert len(reports) == 1
    assert reports[0]["package"] == _PKG_A.name
    assert reports[0]["findings"] == [
        {"verifier": _CRITICAL_FINDING.verifier, "finding": _CRITICAL_FINDING.finding}
    ]
