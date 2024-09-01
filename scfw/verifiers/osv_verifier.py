"""
Defines an installation target verifier that uses OSV.dev's database of vulnerable
and malicious open source software packages.
"""

from typing import Optional

import requests

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier

OSV_ECOSYSTEMS = {ECOSYSTEM.PIP: "PyPI", ECOSYSTEM.NPM: "npm"}

OSV_DEV_QUERY_URL = "https://api.osv.dev/v1/query"


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

    def verify(self, target: InstallTarget) -> Optional[str]:
        """
        Query an given installation target against the OSV.dev database.

        Args:
            target: The installation target to query.

        Returns:
            An OSV.dev finding for the target or `None` if no findings exist.

        Raises:
            requests.HTTPError:
                An error occurred while querying an installation target against the OSV.dev API.
        """
        query = {
            "version": target.version,
            "package": {
                "name": target.package,
                "ecosystem": OSV_ECOSYSTEMS[target.ecosystem]
            }
        }
        request = requests.post(OSV_DEV_QUERY_URL, json=query)
        request.raise_for_status()

        if (vulns := request.json().get("vulns")):
            osv_id = None
            for vuln in vulns:
                if (osv_id := vuln.get("id")):
                    break
            return (
                f"An OSV.dev disclosure for package {target.package} exists (OSVID: {osv_id if osv_id else 'Unknown'})"
            )
        else:
            return None
