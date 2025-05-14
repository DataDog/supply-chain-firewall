"""
A class for structuring and displaying the results of installation target verification.
"""

from collections.abc import Iterable
from typing import Optional

from scfw.package import Package


class VerificationReport:
    """
    A structured report containing findings resulting from installation target verification.
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

        def show_findings(target: Package, findings: list[str]) -> str:
            return (
                f"Installation target {target}:\n" + '\n'.join(map(show_finding, findings))
            )

        return '\n'.join(
            show_findings(target, findings) for target, findings in self._report.items()
        )

    def get(self, target: Package) -> Optional[list[str]]:
        """
        Get the findings for the given installation target.

        Args:
            target: The `Package` to look up in the report.

        Returns:
            The findings for `target` contained in the report or `None` if `target`
            is not reported on.
        """
        return self._report.get(target)

    def insert(self, target: Package, finding: str) -> None:
        """
        Insert the given installation target and finding into the report.

        Args:
            target: The `Package` to insert into the report.
            findings: The finding being reported for `target`.
        """
        if target in self._report:
            self._report[target].append(finding)
        else:
            self._report[target] = [finding]

    def targets(self) -> Iterable[Package]:
        """
        Return an iterator over `Package` mentioned in the report.
        """
        return (target for target in self._report)
