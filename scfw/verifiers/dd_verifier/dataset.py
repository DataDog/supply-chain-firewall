"""
Utilities for downloading and caching the malicious package dataset manifests.
"""

import glob
import json
import logging
import os
from pathlib import Path
import re
from typing import Optional, TypeAlias

import requests

from scfw.ecosystem import ECOSYSTEM

_log = logging.getLogger(__name__)

_DD_DATASET_SAMPLES_URL = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples"

Manifest: TypeAlias = dict[str, list[str]]
"""
A malicious packages dataset manifest mapping package names to affected versions.
"""


def download_manifest(ecosystem: ECOSYSTEM) -> tuple[Optional[str], Manifest]:
    """
    Download the dataset manifest for the given `ecosystem`.
    """
    request = requests.get(_manifest_url(ecosystem))
    request.raise_for_status()

    return (_extract_etag_header(request.headers.get("ETag", "")), request.json())


def cache_latest_manifest(cache_dir: Path, ecosystem: ECOSYSTEM) -> Manifest:
    """
    Return the dataset manifest for the given `ecosystem` and update its cache in `cache_dir`.
    """
    update_cache = True
    cached_manifest_file = None
    latest_etag, latest_manifest = None, None

    manifest_files = glob.glob(str(cache_dir / f"{ecosystem}*.json"))

    try:
        if (
            manifest_files
            and (cached_manifest_file := Path(manifest_files[0]))
            and (last_etag := _extract_etag_file_name(ecosystem, cached_manifest_file.name))
        ):
            latest_etag, manifest = _update_manifest(ecosystem, last_etag)

            if latest_etag == last_etag:
                _log.info(f"Loading malicious {ecosystem} packages dataset from cache")
                update_cache = False
                with open(cached_manifest_file) as f:
                    latest_manifest = json.load(f)
            else:
                latest_manifest = manifest
        else:
            latest_etag, latest_manifest = download_manifest(ecosystem)
    except requests.HTTPError:
        _log.warning(f"Failed to obtain malicious {ecosystem} packages metadata or dataset from GitHub")

        if cached_manifest_file:
            _log.warning(f"Using cached copy of malicious {ecosystem} packages dataset after GitHub failure")
            with open(cached_manifest_file) as f:
                return json.load(f)
        else:
            raise RuntimeError(
                f"Failed to read cached malicious {ecosystem} packages dataset after GitHub failure"
            )

    if not latest_manifest:
        raise RuntimeError(f"Failed to obtain malicious {ecosystem} packages dataset")

    if update_cache:
        _log.info(f"Updating cached copy of malicious {ecosystem} packages dataset")
        try:
            if cached_manifest_file:
                os.remove(cached_manifest_file)
            cached_manifest_file = cache_dir / f"{ecosystem}{latest_etag if latest_etag else ''}.json"
            with open(cached_manifest_file, 'w') as f:
                json.dump(latest_manifest, f)
        except Exception as e:
            _log.warning(f"Failed to update cached copy of malicious {ecosystem} packages dataset: {e}")

    return latest_manifest


def _update_manifest(ecosystem: ECOSYSTEM, etag: str) -> tuple[Optional[str], Optional[Manifest]]:
    """
    Get the latest dataset manifest for the given `ecosystem` relative to the given `etag`.
    """
    request = requests.get(_manifest_url(ecosystem), headers={"If-None-Match": f'W/"{etag}"'})
    request.raise_for_status()

    if request.status_code == requests.codes.NOT_MODIFIED:
        return (etag, None)

    return (_extract_etag_header(request.headers.get("ETag", "")), request.json())


def _extract_etag_header(s: str) -> Optional[str]:
    """
    Extract an ETag from the given header string.
    """
    match = re.search('W/"(.*)"', s)
    return match.group(1) if match else None


def _extract_etag_file_name(ecosystem: ECOSYSTEM, s: str) -> Optional[str]:
    """
    Extract an ETag from the file name of the given `ecosystem` manifest cache.
    """
    match = re.search(f"{ecosystem}(.*).json", s)
    return match.group(1) if match else None


def _manifest_url(ecosystem: ECOSYSTEM) -> str:
    """
    Construct the GitHub download URL for the given `ecosystem` manifest file.
    """
    return f"{_DD_DATASET_SAMPLES_URL}/{str(ecosystem).lower()}/manifest.json"
