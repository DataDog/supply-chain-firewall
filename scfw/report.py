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
    A message from a verifier indicating why it was unable to verify.
    """
    verifier: str
    message: str


FindingsReport: TypeAlias = dict[Package, set[Finding]]
"""
A structured report containing findings for a set of `Package`.
"""

UnverifiedReport: TypeAlias = dict[Package, set[Unverified]]
"""
A structured report containing unverifiable messages for a set of `Package`.
"""


class VerificationReport:
    """
    A structured report containing the results of verifying a set of `Package`.
    """
    def __init__(self) -> None:
        """
        Initialize an empty `VerificationReport`.
        """
        self._clean: set[Package] = set()
        self._findings: FindingsReport = {}
        self._unverified: UnverifiedReport = {}

    def get_clean(self) -> set[Package]:
        """
        Return the set of "clean" packages contained in the report.

        Returns:
            A `set[Package]` containing those packages in the report which were
            able to be verified successfully and for which there were no findings.
        """
        return set(self._clean)

    def get_findings(self, severity: FindingSeverity) -> FindingsReport:
        """
        Return a structured report on packages that had findings of a given severity.

        Returns:
            A `FindingsReport` covering the `Package` contained in the report that
            had reported findings of the given `FindingSeverity.
        """
        severity_findings = {}

        for package, findings in self._findings.items():
            if (s := {finding for finding in findings if finding.severity == severity}):
                severity_findings[package] = s

        return severity_findings

    def get_unverified(self) -> UnverifiedReport:
        """
        Return a structured report on packages that were unable to be verified.

        Returns:
            A `UnverifiedReport` covering the `Package` contained in the report
            that were unable to be verified by at least one verifier.
        """
        return {package: set(unverified) for package, unverified in self._unverified.items()}

    def insert_clean(self, package: Package) -> None:
        """
        Insert a clean package into the report.

        Args:
            package:
                The clean `Package` to be inserted into the report.

                This function is a no-op if `package` already has findings in the report
                or is known to be unverifiable by at least one verifier.
        """
        if package in self._findings or package in self._unverified:
            return

        self._clean.add(package)

    def insert_finding(self, package: Package, finding: Finding) -> None:
        """
        Insert a finding for a given package into the report.

        Args:
            `package`: The `Package` the finding pertains to.
            `finding`: The `Finding` to be inserted for `package`.
        """
        if package not in self._findings:
            self._findings[package] = set()
        self._findings[package].add(finding)

        if package in self._clean:
            self._clean.remove(package)

    def insert_unverified(self, package: Package, unverified: Unverified) -> None:
        """
        Insert an unverified message for a given package into the report.

        Args:
            `package`: The `Package` the unverified message pertains to.
            `unverified`: The `Unverified` message to be inserted for `package`.
        """
        if package not in self._unverified:
            self._unverified[package] = set()
        self._unverified[package].add(unverified)

        if package in self._clean:
            self._clean.remove(package)

    def packages(self) -> set[Package]:
        """
        Return the set of packages contained in the report.

        Returns:
            A `set[Package]` containing all packages mentioned in the report.
        """
        return self._clean | set(self._findings) | set(self._unverified)


def show_reports(findings_reports: list[FindingsReport], unverified_report: UnverifiedReport) -> str:
    """
    Return a pretty-printed string representation of the given reports.

    Args:
        `findings_reports`: A `list[FindingsReports]` to be formatted for printing.
        'unverified_report`: An `UnverifiedReport` to be formatted for printing.

    Returns:
        A pretty-printed `str` representation of the given reports suitable for displaying
        to the user during a run of Supply-Chain Firewall.
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
