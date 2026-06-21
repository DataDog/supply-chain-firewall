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


def show_reports(findings_reports: list[FindingsReport], unverified_report: UnverifiedReport) -> str:
    """
    Lorem ipsum dolor sit amet.
    """
    def show_line(linenum: int, line: str) -> str:
        return (f"  - {line}" if linenum == 0 else f"    {line}")

    def show_finding(finding: str) -> str:
        return '\n'.join(
            show_line(linenum, line) for linenum, line in enumerate(finding.split('\n'))
        )

    def show_output(package: Package, findings: list[str]) -> str:
        return f"Package {package}:\n" + '\n'.join(map(show_finding, findings))

    # Combine the given `FindingsReport` into a single one
    combined_findings_report: FindingsReport = {}
    for findings_report in findings_reports:
        for package, findings in findings_report.items():
            if package not in combined_findings_report:
                combined_findings_report[package] = set(findings)
            else:
                combined_findings_report[package] |= findings

    # Sort the findings for each package based on severity
    sorted_findings = {
        package: sorted(findings, key=lambda f: f.severity)
        for package, findings in combined_findings_report.items()
    }

    # Prepare the findings + unverified output for each package
    combined_output = {}
    for package in set(sorted_findings) | set(unverified_report):
        findings_output = list(map(lambda f: f.finding, sorted_findings.get(package, [])))
        unverified_output = list(map(lambda u: u.message, unverified_report.get(package, {})))
        combined_output[package] = findings_output + unverified_output

    # Print the output to string, alphabetized by package name
    return '\n'.join(
        show_output(package, combined_output[package])
        for package in sorted(set(sorted_findings) | set(unverified_report), key=str)
    )
