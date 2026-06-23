"""
Tests of the `VerificationReport` class.
"""

import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.report import VerificationReport, VerifierErrorMessage
from scfw.verifier import Finding, FindingSeverity

from tests.utils import build_registry_package


_PKG_A = build_registry_package(ECOSYSTEM.PyPI, "requests", "2.31.0")
_PKG_B = build_registry_package(ECOSYSTEM.PyPI, "numpy", "1.26.0")
_PKG_C = build_registry_package(ECOSYSTEM.Npm, "lodash", "4.17.21")

_CRITICAL_FINDING = Finding("verifier-a", FindingSeverity.CRITICAL, "critical issue")
_WARNING_FINDING = Finding("verifier-b", FindingSeverity.WARNING, "warning issue")

_ERROR_MESSAGE = VerifierErrorMessage("verifier-a", "package not sourced from main registry")


def test_empty_report_get_clean():
    """
    A freshly initialized `VerificationReport` has no clean packages.
    """
    assert VerificationReport().get_clean() == set()


def test_empty_report_get_findings():
    """
    A freshly initialized `VerificationReport` has no findings at any severity level.
    """
    assert VerificationReport().get_findings() == {}


def test_empty_report_get_unverifiable():
    """
    A freshly initialized `VerificationReport` has no unverifiable packages.
    """
    assert VerificationReport().get_unverifiable() == {}


def test_empty_report_packages():
    """
    A freshly initialized `VerificationReport` contains no packages.
    """
    assert VerificationReport().packages() == set()


def test_insert_clean_appears_in_get_clean():
    """
    A clean package inserted into the report is returned by `get_clean()`.
    """
    report = VerificationReport()
    report.insert_clean(_PKG_A)
    assert _PKG_A in report.get_clean()


def test_insert_clean_appears_in_packages():
    """
    A clean package inserted into the report is returned by `packages()`.
    """
    report = VerificationReport()
    report.insert_clean(_PKG_A)
    assert _PKG_A in report.packages()


def test_insert_clean_not_in_findings_or_unverifiable():
    """
    A clean package does not appear in `get_findings()` or `get_unverifiable()`.
    """
    report = VerificationReport()
    report.insert_clean(_PKG_A)
    assert report.get_findings() == {}
    assert report.get_unverifiable() == {}


def test_insert_clean_multiple_packages():
    """
    Multiple clean packages inserted into the report are all returned by `get_clean()`.
    """
    report = VerificationReport()
    for pkg in (_PKG_A, _PKG_B, _PKG_C):
        report.insert_clean(pkg)
    assert report.get_clean() == {_PKG_A, _PKG_B, _PKG_C}


def test_insert_clean_noop_if_package_has_finding():
    """
    `insert_clean()` is a no-op if the package already has a finding in the report.
    """
    report = VerificationReport()
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    report.insert_clean(_PKG_A)
    assert _PKG_A not in report.get_clean()


def test_insert_clean_noop_if_package_is_unverifiable():
    """
    `insert_clean()` is a no-op if the package is already marked unverifiable.
    """
    report = VerificationReport()
    report.insert_unverifiable(_PKG_B, _ERROR_MESSAGE)
    report.insert_clean(_PKG_B)
    assert _PKG_B not in report.get_clean()


def test_insert_clean_idempotent():
    """
    Inserting the same clean package twice does not produce duplicate entries.
    """
    report = VerificationReport()
    report.insert_clean(_PKG_A)
    report.insert_clean(_PKG_A)
    assert report.get_clean() == {_PKG_A}


@pytest.mark.parametrize("finding,severity", [
    (_CRITICAL_FINDING, FindingSeverity.CRITICAL),
    (_WARNING_FINDING, FindingSeverity.WARNING),
])
def test_insert_finding_appears_in_correct_severity_bucket(finding, severity):
    """
    A finding inserted into the report appears in `get_findings()` for its severity
    and not in the other severity bucket.
    """
    other = FindingSeverity.WARNING if severity == FindingSeverity.CRITICAL else FindingSeverity.CRITICAL
    report = VerificationReport()
    report.insert_finding(_PKG_A, finding)
    assert report.get_findings() == {_PKG_A: {finding}}
    assert report.get_findings(severity) == {_PKG_A: {finding}}
    assert report.get_findings(other) == {}


def test_insert_finding_multiple_same_severity():
    """
    Multiple findings of the same severity for the same package are all retained.
    """
    f1 = Finding("v1", FindingSeverity.CRITICAL, "issue one")
    f2 = Finding("v2", FindingSeverity.CRITICAL, "issue two")
    report = VerificationReport()
    report.insert_finding(_PKG_A, f1)
    report.insert_finding(_PKG_A, f2)
    assert report.get_findings(FindingSeverity.CRITICAL)[_PKG_A] == {f1, f2}


def test_insert_finding_mixed_severities_same_package():
    """
    A package with findings of different severities has all findings returned by `get_findings()`.
    """
    report = VerificationReport()
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    report.insert_finding(_PKG_A, _WARNING_FINDING)
    assert report.get_findings() == {_PKG_A: {_CRITICAL_FINDING, _WARNING_FINDING}}


def test_insert_finding_multiple_packages():
    """
    Findings for different packages are tracked independently.
    """
    f_b = Finding("verifier-a", FindingSeverity.CRITICAL, "issue in pkg_b")
    report = VerificationReport()
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    report.insert_finding(_PKG_B, f_b)
    assert report.get_findings() == {_PKG_A: {_CRITICAL_FINDING}, _PKG_B: {f_b}}


def test_insert_finding_removes_package_from_clean():
    """
    A package previously marked clean is removed from `get_clean()` once a finding is inserted.
    """
    report = VerificationReport()
    report.insert_clean(_PKG_A)
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    assert _PKG_A not in report.get_clean()


def test_insert_finding_package_appears_in_packages():
    """
    A package with a finding is returned by `packages()`.
    """
    report = VerificationReport()
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    assert _PKG_A in report.packages()


def test_insert_finding_idempotent():
    """
    Inserting the same finding twice does not produce duplicate entries.
    """
    report = VerificationReport()
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    assert report.get_findings() == {_PKG_A: {_CRITICAL_FINDING}}


def test_insert_unverifiable_appears_in_get_unverifiable():
    """
    An unverifiable error message inserted into the report is returned by `get_unverifiable()`.
    """
    report = VerificationReport()
    report.insert_unverifiable(_PKG_B, _ERROR_MESSAGE)
    unverifiable = report.get_unverifiable()
    assert _PKG_B in unverifiable
    assert _ERROR_MESSAGE in unverifiable[_PKG_B]


def test_insert_unverifiable_multiple_error_messages():
    """
    Multiple error messages for the same unverifiable package are all retained.
    """
    em1 = VerifierErrorMessage("v1", "error from v1")
    em2 = VerifierErrorMessage("v2", "error from v2")
    report = VerificationReport()
    report.insert_unverifiable(_PKG_B, em1)
    report.insert_unverifiable(_PKG_B, em2)
    assert report.get_unverifiable()[_PKG_B] == {em1, em2}


def test_insert_unverifiable_removes_package_from_clean():
    """
    A package previously marked clean is removed from `get_clean()` once it is marked unverifiable.
    """
    report = VerificationReport()
    report.insert_clean(_PKG_B)
    report.insert_unverifiable(_PKG_B, _ERROR_MESSAGE)
    assert _PKG_B not in report.get_clean()


def test_insert_unverifiable_package_appears_in_packages():
    """
    A package marked unverifiable is returned by `packages()`.
    """
    report = VerificationReport()
    report.insert_unverifiable(_PKG_B, _ERROR_MESSAGE)
    assert _PKG_B in report.packages()


def test_insert_unverifiable_idempotent():
    """
    Inserting the same error message twice does not produce duplicate entries.
    """
    report = VerificationReport()
    report.insert_unverifiable(_PKG_B, _ERROR_MESSAGE)
    report.insert_unverifiable(_PKG_B, _ERROR_MESSAGE)
    assert len(report.get_unverifiable()[_PKG_B]) == 1


def test_packages_union_of_all_three_buckets():
    """
    `packages()` returns the union of clean, findings, and unverifiable packages.
    """
    report = VerificationReport()
    report.insert_clean(_PKG_C)
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    report.insert_unverifiable(_PKG_B, _ERROR_MESSAGE)
    assert report.packages() == {_PKG_A, _PKG_B, _PKG_C}


def test_packages_no_duplicates_after_clean_to_findings_promotion():
    """
    A package that moves from clean to findings is not double-counted by `packages()`.
    """
    report = VerificationReport()
    report.insert_clean(_PKG_A)
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    assert report.packages() == {_PKG_A}


def test_get_findings_returns_copy():
    """
    Mutating the set returned by `get_findings()` does not affect the report's internal state.
    """
    report = VerificationReport()
    report.insert_finding(_PKG_A, _CRITICAL_FINDING)
    report.get_findings()[_PKG_A].add(_WARNING_FINDING)
    assert report.get_findings() == {_PKG_A: {_CRITICAL_FINDING}}


def test_get_clean_returns_copy():
    """
    Mutating the set returned by `get_clean()` does not affect the report's internal state.
    """
    report = VerificationReport()
    report.insert_clean(_PKG_A)
    report.get_clean().add(_PKG_B)
    assert _PKG_B not in report.get_clean()


def test_get_unverifiable_returns_copy():
    """
    Mutating the set returned by `get_unverifiable()` does not affect the report's internal state.
    """
    report = VerificationReport()
    report.insert_unverifiable(_PKG_B, _ERROR_MESSAGE)
    report.get_unverifiable()[_PKG_B].add(VerifierErrorMessage("other", "extra"))
    assert len(report.get_unverifiable()[_PKG_B]) == 1
