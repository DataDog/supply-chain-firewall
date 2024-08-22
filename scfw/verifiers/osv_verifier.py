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
    def verify(self, target: InstallTarget) -> Optional[str]:
        """
        Query an given installation target against the OSV.dev database.

        Args:
            target: The installation target to query.

        Returns:
            An OSV.dev finding for the target or `None` if no findings exist.
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

        # TODO: Deal with the case of multiple matches
        if (vulns := request.json().get("vulns")):
            osv_id = vulns[0].get("id")
            return f"An OSV.dev disclosure for package {target.package} exists (OSVID: {osv_id})"
        else:
            return None
