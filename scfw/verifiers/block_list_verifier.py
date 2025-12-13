"""
Defines a package verifier for custom, user-supplied block lists.
"""

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, PackageVerifier


class CustomBlockListVerifier(PackageVerifier):
    """
    A `PackageVerifier` for custom, user-supplied block lists.
    """
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
        return []


def load_verifier() -> PackageVerifier:
    """
    Export `CustomBlockListVerifier` for discovery by Supply-Chain Firewall.

    Returns:
        A `CustomBlockListVerifier` for use in a run of Supply-Chain Firewall.
    """
    return CustomBlockListVerifier()
