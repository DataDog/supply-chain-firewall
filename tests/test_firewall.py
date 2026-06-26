"""
Tests of the core firewall logic.
"""

import sys

import pytest
from typing import Optional
from unittest.mock import MagicMock

from scfw.constants import ON_WARNING_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.firewall import _determine_firewall_action, _get_warning_action
from scfw.logger import FirewallAction
from scfw.report import VerificationReport, VerifierErrorMessage
from scfw.verifier import Finding, FindingSeverity

from tests.utils import build_registry_package


_PKG_A = build_registry_package(ECOSYSTEM.PyPI, "requests", "2.31.0")
_PKG_B = build_registry_package(ECOSYSTEM.PyPI, "numpy", "1.24.0")

_CRITICAL_FINDING = Finding("foo", FindingSeverity.CRITICAL, "critical finding")
_WARNING_FINDING = Finding("foo", FindingSeverity.WARNING, "warning finding")

_UNVERIFIABLE = VerifierErrorMessage("foo", "unverified package")


def test_no_findings():
    """
    A verification report with no findings and no unverifiable packages results in an ALLOW action.
    """
    action, severity, relevant = _determine_firewall_action(VerificationReport(), None)

    assert action == FirewallAction.ALLOW
    assert severity is None
    assert relevant is None


def test_critical_findings_blocks():
    """
    A verification report with critical findings results in a BLOCK action with no user warning.
    """
    report = VerificationReport()
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)

    action, severity, relevant = _determine_firewall_action(report, None)

    assert action == FirewallAction.BLOCK
    assert severity == FindingSeverity.CRITICAL
    assert relevant == report.get_findings(FindingSeverity.CRITICAL)


def test_critical_findings_take_precedence_over_warnings():
    """
    When both critical and warning findings are present, the critical findings drive a BLOCK
    action and the warning findings are not included in the result.
    """
    report = VerificationReport()
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    report.insert_finding(_PKG_B, _WARNING_FINDING)

    action, severity, relevant = _determine_firewall_action(report, None)

    assert action == FirewallAction.BLOCK
    assert severity == FindingSeverity.CRITICAL
    assert relevant == report.get_findings(FindingSeverity.CRITICAL)


def test_critical_findings_take_precedence_over_unverifiable():
    """
    When both critical findings and unverifiable packages are present, the critical findings drive
    a BLOCK action and the unverifiable packages are not included in the result.
    """
    report = VerificationReport()
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    report.insert_unverifiable(_PKG_B, _UNVERIFIABLE)

    action, severity, relevant = _determine_firewall_action(report, None)

    assert action == FirewallAction.BLOCK
    assert severity == FindingSeverity.CRITICAL
    assert relevant == report.get_findings(FindingSeverity.CRITICAL)


@pytest.mark.parametrize("warning_action", [FirewallAction.BLOCK, FirewallAction.ALLOW, None])
def test_warning_findings(warning_action: Optional[FirewallAction]):
    """
    A verification report with only warning findings defers to the configured warning action,
    with the user warned and the warning findings returned as relevant findings.
    """
    report = VerificationReport()
    report.insert_finding(_PKG_A, _WARNING_FINDING)

    action, severity, relevant = _determine_firewall_action(report, warning_action)

    assert action == warning_action
    assert severity == FindingSeverity.WARNING
    assert relevant == report.get_findings(FindingSeverity.WARNING)


@pytest.mark.parametrize("warning_action", [FirewallAction.BLOCK, FirewallAction.ALLOW, None])
def test_unverifiable_only(warning_action: Optional[FirewallAction]):
    """
    Unverifiable packages are treated the same as warning-level findings: the configured
    warning action is returned with the user warned. No relevant findings are returned,
    as unverifiable package information is accessible via the verification report itself.
    """
    report = VerificationReport()
    report.insert_unverifiable(_PKG_A, _UNVERIFIABLE)

    action, severity, relevant = _determine_firewall_action(report, warning_action)

    assert action == warning_action
    assert severity == FindingSeverity.WARNING
    assert relevant is None


@pytest.mark.parametrize("warning_action", [FirewallAction.BLOCK, FirewallAction.ALLOW, None])
def test_warning_and_unverifiable_merged(warning_action: Optional[FirewallAction]):
    """
    When both warning findings and unverifiable packages are present, the relevant findings
    returned are a merge of the two reports.
    """
    report = VerificationReport()
    report.insert_finding(_PKG_A, _WARNING_FINDING)
    report.insert_unverifiable(_PKG_B, _UNVERIFIABLE)

    action, severity, relevant = _determine_firewall_action(report, warning_action)

    assert action == warning_action
    assert severity == FindingSeverity.WARNING
    assert relevant == report.get_findings(FindingSeverity.WARNING)


def test_get_warning_action_cli_block():
    """
    The --block-on-warning CLI flag results in a BLOCK warning action.
    """
    assert _get_warning_action(cli_allow_choice=False, cli_block_choice=True) == FirewallAction.BLOCK


def test_get_warning_action_cli_allow():
    """
    The --allow-on-warning CLI flag results in an ALLOW warning action.
    """
    assert _get_warning_action(cli_allow_choice=True, cli_block_choice=False) == FirewallAction.ALLOW


def test_get_warning_action_cli_block_takes_precedence_over_allow():
    """
    When both --block-on-warning and --allow-on-warning are set, block takes precedence.
    """
    assert _get_warning_action(cli_allow_choice=True, cli_block_choice=True) == FirewallAction.BLOCK


def test_get_warning_action_cli_flag_takes_precedence_over_env_var(monkeypatch):
    """
    A CLI flag takes precedence over ON_WARNING_VAR, even when the env var specifies a
    conflicting action.
    """
    monkeypatch.setenv(ON_WARNING_VAR, "ALLOW")
    assert _get_warning_action(cli_allow_choice=False, cli_block_choice=True) == FirewallAction.BLOCK


@pytest.mark.parametrize(
    "env_value,expected",
    [
        ("BLOCK", FirewallAction.BLOCK),
        ("block", FirewallAction.BLOCK),
        ("ALLOW", FirewallAction.ALLOW),
        ("allow", FirewallAction.ALLOW),
    ]
)
def test_get_warning_action_env_var(env_value: str, expected: FirewallAction, monkeypatch):
    """
    A valid `ON_WARNING_VAR` environment variable determines the warning action,
    case-insensitively.
    """
    monkeypatch.setenv(ON_WARNING_VAR, env_value)

    assert _get_warning_action(cli_allow_choice=False, cli_block_choice=False) == expected


def test_get_warning_action_env_var_invalid_falls_through(monkeypatch):
    """
    An invalid `ON_WARNING_VAR` value is ignored and the terminal interactivity check
    is used as the fallback.
    """
    monkeypatch.setenv(ON_WARNING_VAR, "invalid")
    mock_stdin = MagicMock()
    mock_stdin.isatty.return_value = False
    monkeypatch.setattr(sys, "stdin", mock_stdin)

    assert _get_warning_action(cli_allow_choice=False, cli_block_choice=False) == FirewallAction.BLOCK


def test_get_warning_action_env_var_empty_falls_through_silently(monkeypatch):
    """
    An empty `ON_WARNING_VAR` value is treated as unset and the terminal interactivity
    check is used as the fallback, without logging a warning.
    """
    monkeypatch.setenv(ON_WARNING_VAR, "")
    mock_stdin = MagicMock()
    mock_stdin.isatty.return_value = True
    monkeypatch.setattr(sys, "stdin", mock_stdin)

    assert _get_warning_action(cli_allow_choice=False, cli_block_choice=False) is None


def test_get_warning_action_non_interactive_terminal(monkeypatch):
    """
    A non-interactive terminal with no CLI flags or environment variable defaults to BLOCK.
    """
    monkeypatch.delenv(ON_WARNING_VAR, raising=False)
    mock_stdin = MagicMock()
    mock_stdin.isatty.return_value = False
    monkeypatch.setattr(sys, "stdin", mock_stdin)

    assert _get_warning_action(cli_allow_choice=False, cli_block_choice=False) == FirewallAction.BLOCK


def test_get_warning_action_interactive_terminal(monkeypatch):
    """
    An interactive terminal with no CLI flags or environment variable returns None,
    deferring to the user's runtime decision.
    """
    monkeypatch.delenv(ON_WARNING_VAR, raising=False)
    mock_stdin = MagicMock()
    mock_stdin.isatty.return_value = True
    monkeypatch.setattr(sys, "stdin", mock_stdin)

    assert _get_warning_action(cli_allow_choice=False, cli_block_choice=False) is None
