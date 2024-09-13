"""
Defines an installation target verifier that uses OSV.dev's database of vulnerable
and malicious open source software packages.
"""

from typing import Optional

import requests

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier

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
                "ecosystem": _OSV_ECOSYSTEMS[target.ecosystem]
            }
        }
        # The OSV.dev API is sometimes quite slow, hence the generous timeout
        request = requests.post(_OSV_DEV_QUERY_URL, json=query, timeout=10)
        request.raise_for_status()

        if (vulns := request.json().get("vulns")):
            osv_ids = filter(lambda id: id is not None, map(lambda vuln: vuln.get("id"), vulns))
            message = f"An OSV.dev disclosure for package {target.package} exists"
            return message + ''.join(map(lambda id: f"\n  * {_OSV_DEV_URL_PREFIX}/{id}", osv_ids))
        else:
            return None
