"""
Classes for structuring and displaying the results of package verification.
"""

from dataclasses import dataclass
from typing import Optional, TypeAlias

from scfw.package import Package
from scfw.verifier import Finding, FindingSeverity


@dataclass(eq=True, frozen=True)
class VerifierErrorMessage:
    """
    An error message from a given verifier.
    """
    verifier: str
    error_message: str


FindingsReport: TypeAlias = dict[Package, set[Finding]]
"""
A structured report containing findings for a set of `Package`.
"""

UnverifiablePackageReport: TypeAlias = dict[Package, set[VerifierErrorMessage]]
"""
A structured report containing `UnverifiablePackage` error messages for a set of `Package`.
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
        self._unverifiable: UnverifiablePackageReport = {}

    def get_clean(self) -> set[Package]:
        """
        Return the set of "clean" packages contained in the report.

        Returns:
            A `set[Package]` containing those packages in the report which were
            able to be verified successfully and for which there were no findings.
        """
        return set(self._clean)

    def get_findings(self, severity: Optional[FindingSeverity] = None) -> FindingsReport:
        """
        Return a structured report on packages that had findings of a given severity.

        Args:
            `severity`:
                An `Optional[FindingSeverity]` describing the severity of the findings of
                interest. If `None`, all findings present in the report are returned.

        Returns:
            A `FindingsReport` covering all findings in the report or optionally only
            those of the given `severity`.
        """
        if severity is None:
            return {
                package: set(findings) for package, findings in self._findings.items()
            }

        severity_findings = {}

        for package, findings in self._findings.items():
            if (s := {finding for finding in findings if finding.severity == severity}):
                severity_findings[package] = s

        return severity_findings

    def get_unverifiable(self) -> UnverifiablePackageReport:
        """
        Return a structured report on packages that were unable to be verified.

        Returns:
            An `UnverifiablePackageReport` covering the `Package` contained in the report
            for which a verifier raised an `UnverifiablePackage` error.
        """
        return {
            package: set(error_messages) for package, error_messages in self._unverifiable.items()
        }

    def insert_clean(self, package: Package) -> None:
        """
        Insert a clean package into the report.

        Args:
            package:
                The clean `Package` to be inserted into the report.

                This function is a no-op if `package` already has findings in the report
                or is known to be unverifiable by at least one verifier.
        """
        if package in self._findings or package in self._unverifiable:
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

    def insert_unverifiable(self, package: Package, error_message: VerifierErrorMessage) -> None:
        """
        Insert an unverifiable package error message for a given package into the report.

        Args:
            `package`: The `Package` the unverified message pertains to.
            `error_message`: The `VerifierErrorMessage` to be inserted for `package`.
        """
        if package not in self._unverifiable:
            self._unverifiable[package] = set()
        self._unverifiable[package].add(error_message)

        if package in self._clean:
            self._clean.remove(package)

    def packages(self) -> set[Package]:
        """
        Return the set of packages contained in the report.

        Returns:
            A `set[Package]` containing all packages mentioned in the report.
        """
        return self._clean | set(self._findings) | set(self._unverifiable)


def show_reports(
    findings_reports: list[FindingsReport],
    unverifiable_report: UnverifiablePackageReport,
) -> str:
    """
    Return a pretty-printed string representation of the given reports.

    Args:
        `findings_reports`: A `list[FindingsReports]` to be formatted for printing.
        'unverifiable_report`: An `UnverifiablePackageReport` to be formatted for printing.

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

    all_packages = set(sorted_findings) | set(unverifiable_report)

    # Prepare the findings + unverifiable output for each package
    combined_output = {}
    for package in all_packages:
        findings_output = list(map(lambda f: f.finding, sorted_findings.get(package, [])))
        unverifiable_output = list(
            map(lambda u: u.error_message, unverifiable_report.get(package, {}))
        )
        combined_output[package] = findings_output + unverifiable_output

    # Print the output to string, alphabetized by package name
    return '\n'.join(
        show_output(package, combined_output[package])
        for package in sorted(all_packages, key=str)
    )
