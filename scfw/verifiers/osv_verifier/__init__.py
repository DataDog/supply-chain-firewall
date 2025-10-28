"""
Defines a package verifier for the OSV.dev advisory database.
"""

import functools
import logging
import os
from pathlib import Path
import re

import requests

from scfw.constants import SCFW_HOME_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity, PackageVerifier
from scfw.verifiers.osv_verifier.osv_advisory import OsvAdvisory

_log = logging.getLogger(__name__)

_OSV_DEV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_DEV_VULN_URL_PREFIX = "https://osv.dev/vulnerability"
_OSV_DEV_LIST_URL_PREFIX = "https://osv.dev/list"

OSV_VERIFIER_HOME = Path("osv_verifier/")
"""
The `OsvVerifier` home directory, relative to `SCFW_HOME`.
"""

OSV_IGNORE_LIST_DEFAULT = OSV_VERIFIER_HOME / "ignore.txt"
"""
The default filepath where `OsvVerifier` looks for an ignore list of OSV advisory IDs.
"""

OSV_IGNORE_LIST_VAR = "SCFW_OSV_VERIFIER_IGNORE"
"""
The environment variable under which `OsvVerifier` looks for a filepath to an ignore list
of OSV advisory IDs.
"""


class OsvVerifier(PackageVerifier):
    """
    A `PackageVerifier` for the OSV.dev advisory database.
    """
    def __init__(self):
        """
        Initialize a new `OsvVerifier`.
        """
        def read_ignore_list(ignore_list: Path) -> set[str]:
            with open(ignore_list) as f:
                osv_ids = set(f.read().split())
                ignored_osv_ids = set(filter(lambda id: not id.startswith("MAL"), osv_ids))
                if ignored_osv_ids != osv_ids:
                    _log.warning("OSV malicious package (MAL) advisories will not be ignored")
                return ignored_osv_ids

        self.ignored_osv_ids = set()

        ignore_list = None
        if (filepath := os.getenv(OSV_IGNORE_LIST_VAR)):
            ignore_list = Path(filepath)
        elif (home_dir := os.getenv(SCFW_HOME_VAR)):
            ignore_list = Path(home_dir) / OSV_IGNORE_LIST_DEFAULT

        if not (ignore_list and ignore_list.is_file()):
            return

        _log.info(f"Reading IDs of ignored OSV advisories from {ignore_list}")
        try:
            self.ignored_osv_ids = read_ignore_list(ignore_list)
        except Exception as e:
            _log.warning(f"Failed to read OSV advisory ignore list from {ignore_list}: {e}")

    @classmethod
    def name(cls) -> str:
        """
        Return the `OsvVerifier` name string.

        Returns:
            The class' constant name string: `"OsvVerifier"`.
        """
        return "OsvVerifier"

    @classmethod
    def supported_ecosystems(cls) -> set[ECOSYSTEM]:
        """
        Return the set of package ecosystems supported by `OsvVerifier`.

        Returns:
            The class' constant set of supported ecosystems: `{ECOSYSTEM.Go, ECOSYSTEM.Npm, ECOSYSTEM.PyPI}`.
        """
        return {ECOSYSTEM.Go, ECOSYSTEM.Npm, ECOSYSTEM.PyPI}

    def verify(self, package: Package) -> list[tuple[FindingSeverity, str]]:
        """
        Query a given package against the OSV.dev database.

        Args:
            package: The `Package` to query.

        Returns:
            A list containing any findings for the given package, obtained by querying
            the OSV.dev API.

            OSV.dev advisories with `MAL` IDs are treated as `CRITICAL` findings and all
            others are treated as `WARNING`.  *It is very important to note that most but
            **not all** OSV.dev malicious package advisories have `MAL` IDs.*

        Raises:
            requests.HTTPError:
                An error occurred while querying a package against the OSV.dev API.
        """
        def finding(osv: OsvAdvisory) -> str:
            kind = "malicious package " if osv.id.startswith("MAL") else ""
            severity_tag = f"[{osv.severity}] " if osv.severity else ""
            return (
                f"An OSV.dev {kind}advisory exists for package {package}:\n"
                f"  * {severity_tag}{_OSV_DEV_VULN_URL_PREFIX}/{osv.id}"
            )

        def failure_message() -> str:
            return (
                f"Failed to verify package {package} via the OSV.dev API.\n"
                f"Before proceeding, please check the OSV.dev website for advisories related to this package.\n"
                f"DO NOT PROCEED if the package has advisories with a MAL ID: it is very likely malicious.\n"
                f"  * {_OSV_DEV_LIST_URL_PREFIX}?q={package.name}&ecosystem={str(package.ecosystem)}"
            )

        if package.ecosystem not in self.supported_ecosystems():
            return [(FindingSeverity.WARNING, f"Package ecosystem {package.ecosystem} is not supported")]

        vulns = []
        query = {
            "version": package.version,
            "package": {
                "name": package.name,
                "ecosystem": str(package.ecosystem)
            }
        }

        try:
            while True:
                # The OSV.dev API is sometimes quite slow, hence the generous timeout
                request = requests.post(_OSV_DEV_QUERY_URL, json=query, timeout=10)
                request.raise_for_status()
                response = request.json()

                if (response_vulns := response.get("vulns")):
                    vulns.extend(response_vulns)

                query["page_token"] = response.get("next_page_token")

                if not query["page_token"]:
                    break

            if not vulns:
                return []

            osvs = set(map(OsvAdvisory.from_json, filter(lambda vuln: vuln.get("id"), vulns)))
            mal_osvs = set(filter(lambda osv: osv.id.startswith("MAL"), osvs))
            non_mal_osvs = set(
                filter(
                    lambda osv: not any(re.fullmatch(ignored, osv.id) for ignored in self.ignored_osv_ids),
                    osvs - mal_osvs,
                )
            )

            osv_sort_key = functools.cmp_to_key(OsvAdvisory.compare_severities)
            sorted_mal_osvs = sorted(mal_osvs, reverse=True, key=osv_sort_key)
            sorted_non_mal_osvs = sorted(non_mal_osvs, reverse=True, key=osv_sort_key)

            return (
                [(FindingSeverity.CRITICAL, finding(osv)) for osv in sorted_mal_osvs]
                + [(FindingSeverity.WARNING, finding(osv)) for osv in sorted_non_mal_osvs]
            )

        except requests.exceptions.RequestException as e:
            _log.warning(f"Failed to query OSV.dev API for package {package}: {e}")
            return [(FindingSeverity.WARNING, failure_message())]

        except Exception as e:
            _log.warning(f"Verification failed for package {package}: {e}")
            return [(FindingSeverity.WARNING, failure_message())]


def load_verifier() -> PackageVerifier:
    """
    Export `OsvVerifier` for discovery by Supply-Chain Firewall.

    Returns:
        An `OsvVerifier` for use in a run of Supply-Chain Firewall.
    """
    return OsvVerifier()
