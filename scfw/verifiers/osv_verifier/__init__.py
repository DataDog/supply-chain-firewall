"""
Defines a package verifier for the OSV.dev advisory database.
"""

import functools
import logging

import requests

from scfw.package import Package
from scfw.verifier import FindingSeverity, PackageVerifier
from scfw.verifiers.osv_verifier.osv_advisory import OsvAdvisory

_log = logging.getLogger(__name__)

_OSV_DEV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_DEV_VULN_URL_PREFIX = "https://osv.dev/vulnerability"
_OSV_DEV_LIST_URL_PREFIX = "https://osv.dev/list"


class OsvVerifier(PackageVerifier):
    """
    A `PackageVerifier` for the OSV.dev advisory database.
    """
    @classmethod
    def name(cls) -> str:
        """
        Return the `OsvVerifier` name string.

        Returns:
            The class' constant name string: `"OsvVerifier"`.
        """
        return "OsvVerifier"

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

        vulns = []

        query = {
            "version": package.version,
            "package": {
                "name": package.name,
                "ecosystem": str(package.ecosystem)
            }
        }

        failure_message = (
            f"Failed to verify package {package} via the OSV.dev API.\n"
            f"Before proceeding, please check the OSV.dev website for advisories related to this package.\n"
            f"DO NOT PROCEED if the package has advisories with a MAL ID: it is very likely malicious.\n"
            f"  * {_OSV_DEV_LIST_URL_PREFIX}?q={package.name}&ecosystem={str(package.ecosystem)}"
        )

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
            non_mal_osvs = osvs - mal_osvs

            osv_sort_key = functools.cmp_to_key(OsvAdvisory.compare_severities)
            sorted_mal_osvs = sorted(mal_osvs, reverse=True, key=osv_sort_key)
            sorted_non_mal_osvs = sorted(non_mal_osvs, reverse=True, key=osv_sort_key)

            return (
                [(FindingSeverity.CRITICAL, finding(osv)) for osv in sorted_mal_osvs]
                + [(FindingSeverity.WARNING, finding(osv)) for osv in sorted_non_mal_osvs]
            )

        except requests.exceptions.RequestException as e:
            _log.warning(f"Failed to query OSV.dev API for package {package}: {e}")
            return [(FindingSeverity.WARNING, failure_message)]

        except Exception as e:
            _log.warning(f"Verification failed for package {package}: {e}")
            return [(FindingSeverity.WARNING, failure_message)]


def load_verifier() -> PackageVerifier:
    """
    Export `OsvVerifier` for discovery by Supply-Chain Firewall.

    Returns:
        An `OsvVerifier` for use in a run of Supply-Chain Firewall.
    """
    return OsvVerifier()
