"""
Defines an installation target verifier that uses OSV.dev's database of vulnerable
and malicious open source software packages.
"""

from dataclasses import dataclass
import logging

import requests

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget
from scfw.verifier import FindingSeverity, InstallTargetVerifier

_log = logging.getLogger(__name__)

_OSV_ECOSYSTEMS = {ECOSYSTEM.PIP: "PyPI", ECOSYSTEM.NPM: "npm"}

_OSV_DEV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_DEV_VULN_URL_PREFIX = "https://osv.dev/vulnerability"
_OSV_DEV_LIST_URL_PREFIX = "https://osv.dev/list"


@dataclass(eq=True, frozen=True)
class OsvAdvisory:
    """
    A representation of an OSV advisory containing only the fields relevant
    to installation target verification.
    """
    id: str

    @classmethod
    def from_json(cls, osv_json: dict) -> "OsvAdvisory":
        """
        Convert a JSON-formatted OSV advisory into an `OsvAdvisory`.

        Args:
            osv_json: The JSON-formatted OSV advisory to be converted.

        Returns:
            An `OsvAdvisory` derived from the content of the given JSON.

        Raises:
            ValueError: The advisory was malformed or missing required information.
        """
        if (id := osv_json.get("id")):
            return cls(id)
        else:
            raise ValueError("Encountered OSV advisory with missing ID field")


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
        def mal_finding(osv: OsvAdvisory) -> str:
            return (
                f"An OSV.dev malicious package disclosure exists for package {target}:\n"
                f"  * {_OSV_DEV_VULN_URL_PREFIX}/{osv.id}"
            )

        def non_mal_finding(osv: OsvAdvisory) -> str:
            return (
                f"An OSV.dev disclosure exists for package {target}:\n"
                f"  * {_OSV_DEV_VULN_URL_PREFIX}/{osv.id}"
            )

        def error_message(e: str) -> str:
            url = f"{_OSV_DEV_LIST_URL_PREFIX}?q={target.package}&ecosystem={_OSV_ECOSYSTEMS[target.ecosystem]}"
            return (
                f"Failed to verify target against OSV.dev: {e if e else 'An unspecified error occurred'}.\n"
                f"Before proceeding, please check for OSV.dev advisories related to this target.\n"
                f"DO NOT PROCEED if it has an advisory with a MAL ID: it is very likely malicious.\n"
                f"  * {url}"
            )

        vulns = []

        query = {
            "version": target.version,
            "package": {
                "name": target.package,
                "ecosystem": _OSV_ECOSYSTEMS[target.ecosystem]
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
            non_mal_osvs = osvs - mal_osvs

            return (
                [(FindingSeverity.CRITICAL, mal_finding(osv)) for osv in mal_osvs]
                + [(FindingSeverity.WARNING, non_mal_finding(osv)) for osv in non_mal_osvs]
            )

        except requests.exceptions.RequestException as e:
            _log.warning(f"Failed to query OSV.dev API: returning WARNING finding for target {target}")
            return [(FindingSeverity.WARNING, error_message(str(e)))]


def load_verifier() -> InstallTargetVerifier:
    """
    Export `OsvVerifier` for discovery by the firewall.

    Returns:
        An `OsvVerifier` for use in a run of the supply chain firewall.
    """
    return OsvVerifier()
