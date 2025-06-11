"""
A class for structuring and displaying the results of package verification.
"""

from collections.abc import Iterable
from typing import Optional
from typing_extensions import Self

from scfw.package import Package


class VerificationReport:
    """
    A structured report containing findings resulting from package verification.
    """
    def __init__(self) -> None:
        """
        Initialize a new, empty `VerificationReport`.
        """
        self._report: dict[Package, list[str]] = {}

    def __len__(self) -> int:
        """
        Return the number of entries in the report.
        """
        return len(self._report)

    def __str__(self) -> str:
        """
        Return a human-readable version of a verification report.

        Returns:
            A `str` containing the formatted verification report.
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
        Extend a `VerificationReport` with additional findings from another.

        Args:
            other: The `VerificationReport` whose findings will be extended into `self`.
        """
        for package, findings in other._report.items():
            if package in self._report:
                self._report[package].extend(findings)
            else:
                self._report[package] = findings

    def packages(self) -> Iterable[Package]:
        """
        Return an iterator over `Package` mentioned in the report.
        """
        return (package for package in self._report)
