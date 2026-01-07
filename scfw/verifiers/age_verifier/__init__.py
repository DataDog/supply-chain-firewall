"""
Defines a package verifier for warning on packages that were created too recently
based on a user-configurable minimum age.
"""

from datetime import datetime, timedelta, timezone
import logging
import os

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, PackageVerifier
import scfw.verifiers.age_verifier.npm as npm
import scfw.verifiers.age_verifier.pypi as pypi

_log = logging.getLogger(__name__)

MINIMUM_AGE_DEFAULT = 24
"""
The default minimum age, expressed in hours.
"""

MINIMUM_AGE_VAR = "SCFW_PACKAGE_MINIMUM_AGE"
"""
The environment variable under which `PackageAgeVerifier` looks for a user-provided
minimum age, expressed as a positive integer representing the number of hours below
which a warning is warranted.
"""


class PackageAgeVerifier(PackageVerifier):
    """
    A package verifier for warning on packages that were created too recently based on
    a user-configurable minimum age, expressed as a positive integer representing the
    number of hours below which a warning is warranted.
    """
    def __init__(self):
        """
        Initialize a new `PackageAgeVerifier`.
        """
        minimum_age = MINIMUM_AGE_DEFAULT

        if (m := os.getenv(MINIMUM_AGE_VAR)):
            try:
                user_minimum_age = int(m)
                if user_minimum_age < 0:
                    raise ValueError("Minimum age cannot be negative")

                minimum_age = user_minimum_age
            except Exception:
                _log.warning(
                    f"Invalid minimum package age '{m}', using default value of {MINIMUM_AGE_DEFAULT} hours"
                )

        self.minimum_age = timedelta(hours=minimum_age)

    @classmethod
    def name(cls) -> str:
        """
        Return the `PackageAgeVerifier` name string.

        Returns:
            The class' constant name string: `"PackageAgeVerifier"`.
        """
        return "PackageAgeVerifier"

    @classmethod
    def supported_ecosystems(cls) -> set[ECOSYSTEM]:
        """
        Return the set of package ecosystems supported by `PackageAgeVerifier`.

        Returns:
            The class' constant set of supported ecosystems: `{ECOSYSTEM.Npm, ECOSYSTEM.PyPI}`.
        """
        return {ECOSYSTEM.Npm, ECOSYSTEM.PyPI}

    def verify(self, package: Package) -> list[tuple[FindingSeverity, str]]:
        """
        Determine how recently a given package was created and warn if this is deemed
        too recent based on a user-configurable minimum age.

        Args:
            package: The `Package` to verify.

        Returns:
            A list containing a single `WARNING` finding if `package` is deemed to have
            been created too recently, otherwise an empty list.
        """
        if self.minimum_age == timedelta(0):
            return []

        try:
            match package.ecosystem:
                case ECOSYSTEM.Npm:
                    creation_datetime_utc = npm.get_creation_datetime_utc(package.name)
                case ECOSYSTEM.PyPI:
                    creation_datetime_utc = pypi.get_creation_datetime_utc(package.name)

            if datetime.now(tz=timezone.utc) - creation_datetime_utc < self.minimum_age:
                minimum_age_hours = int(self.minimum_age.total_seconds()) // 3600
                return [(
                    FindingSeverity.WARNING,
                    (
                        f"Package {package.name} was created less than {minimum_age_hours} hours ago"
                        ": treat new packages with caution"
                    ),
                )]

        except Exception as e:
            _log.warning(f"Failed to determine creation datetime for package {package.name}: {e}")

        return []


def load_verifier() -> PackageVerifier:
    """
    Export `PackageAgeVerifier` for discovery by Supply-Chain Firewall.

    Returns:
        A `PackageAgeVerifier` for use in a run of Supply-Chain Firewall.
    """
    return PackageAgeVerifier()
