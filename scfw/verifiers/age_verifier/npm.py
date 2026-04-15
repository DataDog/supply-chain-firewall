"""
Provides utilities for querying the npm registry to discover package publication dates.
"""

from datetime import datetime
from dateutil import parser as datetime_parser

import requests


def get_release_datetime_utc(package_name: str, package_version: str) -> datetime:
    """
    Return the publication date of a given package to npm.

    Args:
        package_name: The `str` package name to query.
        package_version: The `str` package version to query.

    Returns:
        A UTC `datetime` representing the publication date of the given package to npm.

    Raises:
        requests.HTTPError: Failed to query the npm registry.
        requests.exceptions.JSONDecodeError: Failed to parse query response as JSON.
        RuntimeError: Package metadata missing required fields.
        dateutil.ParserError: Failed to parse publication datetime.
    """
    r = requests.get(f"https://registry.npmjs.org/{package_name}")
    r.raise_for_status()

    package_metadata = r.json()
    release_timestamp = package_metadata.get("time", {}).get(package_version)
    if not release_timestamp:
        raise RuntimeError(f"Metadata for npm package {package_name} missing required fields")

    return datetime_parser.parse(release_timestamp)
