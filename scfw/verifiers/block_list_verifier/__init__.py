"""
Defines a package verifier for custom, user-supplied block lists.
"""

import itertools
import logging
import os
from pathlib import Path

from scfw.constants import SCFW_HOME_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, PackageVerifier
from scfw.verifiers.block_list_verifier.findings_map import FindingsMap

_log = logging.getLogger(__name__)

BLOCK_LIST_VERIFIER_HOME = Path("block_list_verifier/")
"""
The `CustomBlockListVerifier` home directory, relative to `SCFW_HOME`.
"""


class CustomBlockListVerifier(PackageVerifier):
    """
    A `PackageVerifier` for custom, user-supplied block lists.
    """
    def __init__(self):
        """
        Initialize a new `CustomBlockListVerifier`.
        """
        def get_matching_files(directory: Path, pattern: str):
            return (f for f in directory.glob(pattern) if f.is_file())

        self._findings_map = FindingsMap()

        if (scfw_home := os.getenv(SCFW_HOME_VAR)):
            block_lists_home = Path(scfw_home) / BLOCK_LIST_VERIFIER_HOME
            if not block_lists_home.is_dir():
                return

            block_lists = itertools.chain(
                get_matching_files(block_lists_home, "*.yml"),
                get_matching_files(block_lists_home, "*.yaml"),
            )
            for block_list in block_lists:
                try:
                    with open(block_list) as f:
                        self._findings_map.merge(FindingsMap.from_yaml(f.read()))
                except Exception as e:
                    _log.warning(f"Failed to import block list file {block_list}: {e}")

    @classmethod
    def name(cls) -> str:
        """
        Return the `CustomBlockListVerifier` name string.

        Returns:
            The class' constant name string: `"CustomBlockListVerifier"`.
        """
        return "CustomBlockListVerifier"

    @classmethod
    def supported_ecosystems(cls) -> set[ECOSYSTEM]:
        """
        Return the set of package ecosystems supported by `CustomBlockListVerifier`.

        Returns:
            The class' constant set of supported ecosystems: `{ECOSYSTEM.Npm, ECOSYSTEM.PyPI}`.
        """
        return {ECOSYSTEM.Npm, ECOSYSTEM.PyPI}

    def verify(self, package: Package) -> list[tuple[FindingSeverity, str]]:
        """
        Determine whether a package is in the user-supplied block list and return
        the appropriate finding.

        Args:
            package: The `Package` to verify.

        Returns:
            A list containing the finding, if any, prescribed for the given `Package` in the
            given user-supplied block list:
              * A single `CRITICAL` finding the block list specifies that `package` should block
              * A single `WARNING` finding when the block list specifies that `package` should warn
            In these cases, the user-supplied message is returned as the text of the finding.
        """
        return self._findings_map.get_findings(package)


def load_verifier() -> PackageVerifier:
    """
    Export `CustomBlockListVerifier` for discovery by Supply-Chain Firewall.

    Returns:
        A `CustomBlockListVerifier` for use in a run of Supply-Chain Firewall.
    """
    return CustomBlockListVerifier()
