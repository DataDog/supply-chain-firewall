from typing import Optional

import requests

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier

OSV_ECOSYSTEMS = {ECOSYSTEM.PIP: "PyPI", ECOSYSTEM.NPM: "npm"}

OSV_DEV_QUERY_URL = "https://api.osv.dev/v1/query"


class OsvVerifier(InstallTargetVerifier):
    def verify(self, target: InstallTarget) -> Optional[str]:
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
            return f"An OSV.dev disclosure for target {target.show()} exists (OSVID: {osv_id})"
        else:
            return None
