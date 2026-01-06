"""
Provides utilities for querying the npm registry to discover package creation dates.
"""

from datetime import datetime, timezone

import requests


def get_creation_datetime_utc(package_name: str) -> datetime:
    """
    Return the creation date for the given npm package.

    Args:
        package_name: The `str` package name whose creation date should be queried.

    Returns:
        A UTC `datetime` representing the creation date of `package_name` on npm.

    Raises:
        requests.HTTPError: Failed to query the npm registry.
        requests.exceptions.JSONDecodeError: Failed to parse query response as JSON.
        RuntimeError: Package metadata missing required fields.
        ValueError: Creation timestamp does not have the expected format.
    """
    r = requests.get(f"https://registry.npmjs.org/{package_name}")
    r.raise_for_status()

    package_metadata = r.json()
    creation_timestamp = package_metadata.get("time", {}).get("created")
    if not creation_timestamp:
        raise RuntimeError(f"Metadata for npm package {package_name} missing required fields")

    creation_datetime = datetime.strptime(creation_timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    creation_datetime_utc = creation_datetime.replace(tzinfo=timezone.utc)

    return creation_datetime_utc
