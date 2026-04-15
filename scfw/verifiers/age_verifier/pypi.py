"""
Provides utilities for querying the PyPI registry to discover package publication dates.
"""

from datetime import datetime
from dateutil import parser as datetime_parser

import requests


def get_release_datetime_utc(package_name: str, package_version) -> datetime:
    """
    Return the publication date of a given package to PyPI.

    Args:
        package_name: The `str` package name to query.
        package_version: The `str` package version to query.

    Returns:
        A UTC `datetime` representing the publication date of the given package to PyPI.

    Raises:
        requests.HTTPError: Failed to query the PyPI registry.
        requests.exceptions.JSONDecodeError: Failed to parse query response as JSON.
        RuntimeError:
            * Package metadata missing required fields.
            * No publication timestamps found for specified release.
        dateutil.ParserError: Failed to parse publication datetime.
    """
    r = requests.get(f"https://pypi.org/pypi/{package_name}/json")
    r.raise_for_status()

    package_metadata = r.json()
    release_metadata = package_metadata.get("releases", {}).get(package_version)
    if not release_metadata:
        raise RuntimeError("Package metadata missing required fields")

    release_datetimes = set()
    for metadata in release_metadata:
        if (release_datetime := metadata.get("upload_time_iso_8601")):
            release_datetimes.add(datetime_parser.parse(release_datetime))

    if not release_datetimes:
        raise RuntimeError(f"No publication timestamp for version {package_version} of package {package_name}")

    return sorted(release_datetimes)[-1]
