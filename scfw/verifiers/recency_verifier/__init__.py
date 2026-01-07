"""
Defines a package verifier for warning on packages that were created too recently
based on a user-configurable recency tolerance.
"""

from datetime import datetime, timedelta, timezone
import logging
import os

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, PackageVerifier
import scfw.verifiers.recency_verifier.npm as npm
import scfw.verifiers.recency_verifier.pypi as pypi

_log = logging.getLogger(__name__)

RECENCY_TOLERANCE_DEFAULT = 24
"""
The default recency tolerance, expressed in hours.
"""

RECENCY_TOLERANCE_VAR = "SCFW_PACKAGE_RECENCY_TOLERANCE"
"""
The environment variable under which `PackageRecencyVerifier` looks for a user-provided
recency tolerance, expressed as a positive integer representing the number of hours
below which a warning is warranted.
"""


class PackageRecencyVerifier(PackageVerifier):
    """
    A package verifier for warning on packages that were created too recently based on
    a user-configurable recency tolerance, expressed as a positive integer representing
    the number of hours below which a warning is warranted.
    """
    def __init__(self):
        """
        Initialize a new `PackageRecencyVerifier`.
        """
        tolerance = RECENCY_TOLERANCE_DEFAULT

        if (t := os.getenv(RECENCY_TOLERANCE_VAR)):
            try:
                user_tolerance = int(t)
                if user_tolerance < 0:
                    raise ValueError("Recency tolerance cannot be negative")

                tolerance = user_tolerance
            except Exception:
                _log.warning(
                    f"Invalid recency tolerance '{t}', using default value of {RECENCY_TOLERANCE_DEFAULT} hours"
                )

        self.tolerance = timedelta(hours=tolerance)

    @classmethod
    def name(cls) -> str:
        """
        Return the `PackageRecencyVerifier` name string.

        Returns:
            The class' constant name string: `"PackageRecencyVerifier"`.
        """
        return "PackageRecencyVerifier"

    @classmethod
    def supported_ecosystems(cls) -> set[ECOSYSTEM]:
        """
        Return the set of package ecosystems supported by `PackageRecencyVerifier`.

        Returns:
            The class' constant set of supported ecosystems: `{ECOSYSTEM.Npm, ECOSYSTEM.PyPI}`.
        """
        return {ECOSYSTEM.Npm, ECOSYSTEM.PyPI}

    def verify(self, package: Package) -> list[tuple[FindingSeverity, str]]:
        """
        Determine how recently a given package was created and warn if this is deemed
        too recent based on a user-configurable tolerance.

        Args:
            package: The `Package` to verify.

        Returns:
            A list containing a single `WARNING` finding if `package` is deemed to have
            been created too recently, otherwise an empty list.
        """
        try:
            match package.ecosystem:
                case ECOSYSTEM.Npm:
                    creation_datetime_utc = npm.get_creation_datetime_utc(package.name)
                case ECOSYSTEM.PyPI:
                    creation_datetime_utc = pypi.get_creation_datetime_utc(package.name)

            if datetime.now(tz=timezone.utc) - creation_datetime_utc < self.tolerance:
                tolerance_hours = int(self.tolerance.total_seconds()) // 3600
                return [(
                    FindingSeverity.WARNING,
                    (
                        f"Package {package.name} was created less than {tolerance_hours} hours ago"
                        ": treat new packages with caution"
                    ),
                )]

        except Exception as e:
            _log.warning(f"Failed to determine creation date for package {package.name}: {e}")

        return []


def load_verifier() -> PackageVerifier:
    """
    Export `PackageRecencyVerifier` for discovery by Supply-Chain Firewall.

    Returns:
        A `PackageRecencyVerifier` for use in a run of Supply-Chain Firewall.
    """
    return PackageRecencyVerifier()
