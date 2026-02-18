"""
Provides utilities for querying the PyPI registry to discover package creation dates.
"""

from datetime import datetime
from dateutil import parser as datetime_parser

import requests


def get_creation_datetime_utc(package_name: str) -> datetime:
    """
    Return the creation date for the given PyPI package.

    Args:
        package_name: The `str` package name whose creation date should be queried.

    Returns:
        A UTC `datetime` representing the creation date of `package_name` on PyPI.

    Raises:
        requests.HTTPError: Failed to query the PyPI registry.
        requests.exceptions.JSONDecodeError: Failed to parse query response as JSON.
        RuntimeError:
            * Package metadata missing required fields.
            * No upload timestamps found in package metadata.
        dateutil.ParserError: Failed to parse publication datetime.
    """
    r = requests.get(f"https://pypi.org/pypi/{package_name}/json")
    r.raise_for_status()

    package_metadata = r.json()
    releases = package_metadata.get("releases")
    if not releases:
        raise RuntimeError("Package metadata missing required fields")

    upload_datetimes = set()
    for _, metadatas in releases.items():
        for metadata in metadatas:
            upload_timestamp = metadata.get("upload_time_iso_8601")
            if not upload_timestamp:
                continue

            upload_datetimes.add(datetime_parser.parse(upload_timestamp))

    if not upload_datetimes:
        raise RuntimeError("No upload timestamps found in package metadata")

    return sorted(upload_datetimes)[0]
