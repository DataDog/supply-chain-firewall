"""
Classes for structuring and displaying the results of package verification.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Optional
from typing_extensions import Self

from scfw.package import Package
from scfw.verifier import FindingSeverity


class FindingsReport:
    """
    A structured report containing verification findings for a set of `Package`.
    """
    def __init__(self) -> None:
        """
        Initialize a new, empty `FindingsReport`.
        """
        self._report: dict[Package, list[str]] = {}

    def __eq__(self, other: object) -> bool:
        """
        Determine whether two `FindingsReport` are equal.
        """
        if not isinstance(other, FindingsReport):
            return NotImplemented

        return self._report == other._report

    def __len__(self) -> int:
        """
        Return the number of entries in the report.
        """
        return len(self._report)

    def __str__(self) -> str:
        """
        Return a human-readable version of a findings report.

        Returns:
            A `str` containing the formatted findings report.
        """
        def show_line(linenum: int, line: str) -> str:
            return (f"  - {line}" if linenum == 0 else f"    {line}")

        def show_finding(finding: str) -> str:
            return '\n'.join(
                show_line(linenum, line) for linenum, line in enumerate(finding.split('\n'))
            )

        def show_findings(package: Package, findings: list[str]) -> str:
            return f"Package {package}:\n" + '\n'.join(map(show_finding, findings))

        return '\n'.join(
            show_findings(package, findings) for package, findings in self._report.items()
        )

    @classmethod
    def merge(cls, lhs: Self, rhs: Self) -> Self:
        """
        Merge two `FindingsReports` into a new one containing them both.

        Args:
            lhs: The first `FindingsReport` to be merged.
            rhs: The second `FindingsReport` to be merged.

        Returns:
            A `FindingsReport` containing all of the findings in `lhs` and `rhs`.
        """
        merged = cls()
        merged.extend(lhs)
        merged.extend(rhs)

        return merged

    def get(self, package: Package) -> Optional[list[str]]:
        """
        Get the findings for the given package.

        Args:
            package: The `Package` to look up in the report.

        Returns:
            The reported findings for `package` or `None` if it is not present.
        """
        return self._report.get(package)

    def insert(self, package: Package, finding: str) -> None:
        """
        Insert the given package and finding into the report.

        Args:
            package: The `Package` to insert into the report.
            findings: The finding being reported for `package`.
        """
        if package in self._report:
            self._report[package].append(finding)
        else:
            self._report[package] = [finding]

    def extend(self, other: Self) -> None:
        """
        Extend a `FindingsReport` with additional findings from another.

        Args:
            other: The `FindingsReport` whose findings will be extended into `self`.
        """
        for package, findings in other._report.items():
            if package in self._report:
                self._report[package].extend(findings)
            else:
                self._report[package] = list(findings)

    def packages(self) -> Iterable[Package]:
        """
        Return an iterator over `Package` mentioned in the report.
        """
        return self._report.keys()


@dataclass(eq=True)
class VerificationReport:
    """
    A structured report containing the results of verifying a set of `Package`.
    """
    verification_set: frozenset[Package]
    findings_reports: dict[FindingSeverity, FindingsReport]
    unverifiable: FindingsReport

    def get_findings_report(self, severity: FindingSeverity) -> Optional[FindingsReport]:
        """
        Return the reported `FindingsReport` of the given severity level if one exists.

        Returns:
            The `FindingsReport` of the given `FindingSeverity` contained in the given
            verification report's set of severity-ranked finding reports.
        """
        return self.findings_reports.get(severity)
