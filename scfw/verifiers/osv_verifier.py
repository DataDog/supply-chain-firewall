"""
Defines an installation target verifier that uses OSV.dev's database of vulnerable
and malicious open source software packages.
"""

import requests

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget
from scfw.verifier import FindingSeverity, InstallTargetVerifier

_OSV_ECOSYSTEMS = {ECOSYSTEM.PIP: "PyPI", ECOSYSTEM.NPM: "npm"}

_OSV_DEV_QUERY_URL = "https://api.osv.dev/v1/query"

_OSV_DEV_URL_PREFIX = "https://osv.dev/vulnerability"


class OsvVerifier(InstallTargetVerifier):
    """
    An `InstallTargetVerifier` for the OSV.dev open source vulnerability and
    malicious package database.
    """
    def name(self) -> str:
        """
        Return the `OsvVerifier` name string.

        Returns:
            The class' constant name string: `"OsvVerifier"`.
        """
        return "OsvVerifier"

    def verify(self, target: InstallTarget) -> list[tuple[FindingSeverity, str]]:
        """
        Query an given installation target against the OSV.dev database.

        Args:
            target: The installation target to query.

        Returns:
            A list containing any findings for the given installation target, obtained
            by querying for it against OSV.dev.

            OSV.dev disclosures with `MAL` IDs are treated as `CRITICAL` findings and all
            others are treated as `WARNING`.  *It is very important to note that most but
            **not all** OSV.dev malicious package disclosures have `MAL` IDs.*

        Raises:
            requests.HTTPError:
                An error occurred while querying an installation target against the OSV.dev API.
        """
        def mal_finding(id: str) -> str:
            return (
                f"An OSV.dev malicious package disclosure exists for package {target}:\n"
                f"  * {_OSV_DEV_URL_PREFIX}/{id}"
            )

        def non_mal_finding(id: str) -> str:
            return (
                f"An OSV.dev disclosure exists for package {target}:\n"
                f"  * {_OSV_DEV_URL_PREFIX}/{id}"
            )

        query = {
            "version": target.version,
            "package": {
                "name": target.package,
                "ecosystem": _OSV_ECOSYSTEMS[target.ecosystem]
            }
        }
        # The OSV.dev API is sometimes quite slow, hence the generous timeout
        request = requests.post(_OSV_DEV_QUERY_URL, json=query, timeout=10)
        request.raise_for_status()

        if not (vulns := request.json().get("vulns")):
            return []

        osv_ids = set(filter(lambda id: id is not None, map(lambda vuln: vuln.get("id"), vulns)))
        mal_ids = set(filter(lambda id: id.startswith("MAL"), osv_ids))
        non_mal_ids = osv_ids - mal_ids

        return (
            [(FindingSeverity.CRITICAL, mal_finding(id)) for id in mal_ids]
            + [(FindingSeverity.WARNING, non_mal_finding(id)) for id in non_mal_ids]
        )
