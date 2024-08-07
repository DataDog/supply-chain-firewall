from typing import Optional

import requests

from ecosystem import ECOSYSTEM
from target import InstallTarget
from verifier import InstallTargetVerifier

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

        return request.json().get("id")
