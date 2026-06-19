"""
Classes for structuring and displaying the results of package verification.
"""

from dataclasses import dataclass
from typing import TypeAlias

from scfw.package import Package
from scfw.verifier import Finding, FindingSeverity


@dataclass(eq=True, frozen=True)
class Unverified:
    """
    Lorem ipsum dolor sit amet.
    """
    verifier: str
    message: str


FindingsReport: TypeAlias = dict[Package, set[Finding]]
"""
Lorem ipsum dolor sit amet.
"""

UnverifiedReport: TypeAlias = dict[Package, set[Unverified]]
"""
Lorem ipsum dolor sit amet.
"""


class VerificationReport:
    """
    Lorem ipsum dolor sit amet.
    """
    def __init__(self) -> None:
        """
        Lorem ipsum dolor sit amet.
        """
        self._clean: set[Package] = set()
        self._findings: FindingsReport = {}
        self._unverified: UnverifiedReport = {}

    def get_clean(self) -> set[Package]:
        """
        Lorem ipsum dolor sit amet.
        """
        return set(self._clean)

    def get_findings(self, severity: FindingSeverity) -> FindingsReport:
        """
        Lorem ipsum dolor sit amet.
        """
        severity_findings = {}

        for package, findings in self._findings.items():
            if (s := {finding for finding in findings if finding.severity == severity}):
                severity_findings[package] = s

        return severity_findings

    def get_unverified(self) -> UnverifiedReport:
        """
        Lorem ipsum dolor sit amet.
        """
        return {package: set(unverified) for package, unverified in self._unverified.items()}

    def insert_clean(self, package: Package) -> None:
        """
        Lorem ipsum dolor sit amet.
        """
        if package in self._findings or package in self._unverified:
            return

        self._clean.add(package)

    def insert_finding(self, package: Package, finding: Finding) -> None:
        """
        Lorem ipsum dolor sit amet.
        """
        if package not in self._findings:
            self._findings[package] = set()
        self._findings[package].add(finding)

        if package in self._clean:
            self._clean.remove(package)

    def insert_unverified(self, package: Package, unverified: Unverified) -> None:
        """
        Lorem ipsum dolor sit amet.
        """
        if package not in self._unverified:
            self._unverified[package] = set()
        self._unverified[package].add(unverified)

        if package in self._clean:
            self._clean.remove(package)

    def packages(self) -> set[Package]:
        """
        Lorem ipsum dolor sit amet.
        """
        return self._clean | set(self._findings) | set(self._unverified)
