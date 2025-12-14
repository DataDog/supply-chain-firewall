"""
Defines a package verifier for user-provided findings lists.
"""

import itertools
import logging
import os
from pathlib import Path

from scfw.constants import SCFW_HOME_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, PackageVerifier
from scfw.verifiers.list_verifier.findings_map import FindingsMap

_log = logging.getLogger(__name__)

LIST_VERIFIER_HOME = Path("list_verifier/")
"""
The `FindingsListVerifier` home directory, relative to `SCFW_HOME`.
"""


class FindingsListVerifier(PackageVerifier):
    """
    A `PackageVerifier` for user-provided findings lists.
    """
    def __init__(self):
        """
        Initialize a new `FindingsListVerifier`.
        """
        def get_matching_files(directory: Path, pattern: str):
            return (f for f in directory.glob(pattern) if f.is_file())

        self._findings_map = FindingsMap()

        if (scfw_home := os.getenv(SCFW_HOME_VAR)):
            findings_lists_home = Path(scfw_home) / LIST_VERIFIER_HOME
            if not findings_lists_home.is_dir():
                return

            findings_lists = itertools.chain(
                get_matching_files(findings_lists_home, "*.yml"),
                get_matching_files(findings_lists_home, "*.yaml"),
            )
            for findings_list in findings_lists:
                try:
                    with open(findings_list) as f:
                        self._findings_map.merge(FindingsMap.from_yaml(f.read()))
                except Exception as e:
                    _log.warning(f"Failed to import findings list from file {findings_list}: {e}")

    @classmethod
    def name(cls) -> str:
        """
        Return the `FindingsListVerifier` name string.

        Returns:
            The class' constant name string: `"FindingsListVerifier"`.
        """
        return "FindingsListVerifier"

    @classmethod
    def supported_ecosystems(cls) -> set[ECOSYSTEM]:
        """
        Return the set of package ecosystems supported by `FindingsListVerifier`.

        Returns:
            The class' constant set of supported ecosystems: `{ECOSYSTEM.Npm, ECOSYSTEM.PyPI}`.
        """
        return {ECOSYSTEM.Npm, ECOSYSTEM.PyPI}

    def verify(self, package: Package) -> list[tuple[FindingSeverity, str]]:
        """
        Determine whether a package has findings in the user-provided findings lists.

        Args:
            package: The `Package` to verify.

        Returns:
            All list containing all findings for the given package present in the user-provided
            findings list with which the `FindingsListVerifier` was initialized.
        """
        return self._findings_map.get_findings(package)


def load_verifier() -> PackageVerifier:
    """
    Export `FindingsListVerifier` for discovery by Supply-Chain Firewall.

    Returns:
        A `FindingsListVerifier` for use in a run of Supply-Chain Firewall.
    """
    return FindingsListVerifier()
