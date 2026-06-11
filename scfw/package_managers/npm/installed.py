"""
Provides logic for listing installed npm packages in the active environment.
"""

import json
import logging
from pathlib import Path
import subprocess
from typing import Optional

from scfw.ecosystem import ECOSYSTEM
from scfw.package import LocalPackageSource, Package, RemotePackageSource
from scfw.package_managers.npm.common import FILE_URI_PREFIX, NODE_MODULES_PREFIX

_log = logging.getLogger(__name__)


def list_installed_packages(executable: str) -> list[Package]:
    """
    List all npm packages installed in the active npm environment.

    Args:
        executable: Path to the npm executable.

    Returns:
        A `list[Package]` representing all npm packages installed in the active environment.

    Raises:
        RuntimeError: Received malformed dependencies data from npm.
        subprocess.CalledProcessError: Failed to run `npm list`.
        json.JSONDecodeError: Failed to decode the package report JSON.
    """
    npm_list = subprocess.run(
        [executable, "list", "--all", "--json"],
        check=True, text=True, capture_output=True,
    )

    dependencies = json.loads(npm_list.stdout.strip()).get("dependencies", {})
    if not isinstance(dependencies, dict):
        raise RuntimeError("Received malformed dependencies data from npm")

    resolved_fallback = _load_lock_file_resolved_map(Path.cwd() / "package-lock.json")

    return list(_dependencies_to_packages(dependencies, resolved_fallback))


def _dependencies_to_packages(
    dependencies: dict[str, dict],
    resolved_fallback: dict[tuple[str, str], str],
) -> set[Package]:
    packages = set()

    node_modules_path = Path.cwd() / "node_modules"

    for name, package_data in dependencies.items():
        try:
            if not (version := package_data.get("version")):
                # Skip the whole entry, including any `dependencies` subtree:
                # npm list does not report children under an uninstalled parent
                _log.debug(f"Skipping dependency {name}: not installed")
                continue

            resolved = package_data.get("resolved", "") or resolved_fallback.get((name, version), "")

            # `file:` dependencies reported by `npm list` are relative to `node_modules/`
            local_path = (
                (node_modules_path / resolved[len(FILE_URI_PREFIX):]).resolve()
                if resolved.startswith(FILE_URI_PREFIX) else None
            )

            if (nested := package_data.get("dependencies")):
                nested_fallback = resolved_fallback
                if local_path is not None:
                    lock_file = local_path / "package-lock.json"
                    if lock_file.is_file():
                        nested_fallback = {
                            **resolved_fallback,
                            **_load_lock_file_resolved_map(lock_file),
                        }
                packages |= _dependencies_to_packages(nested, nested_fallback)

            if not resolved:
                _log.info(f"No artifact source data found for installed dependency {name}")

            source: Optional[LocalPackageSource | RemotePackageSource] = None
            if resolved.startswith("http"):
                source = RemotePackageSource(resolved)
            elif local_path is not None:
                if local_path.exists():
                    source = LocalPackageSource(local_path)
                else:
                    _log.warning(
                        f"Could not resolve local source path for installed dependency {name}: "
                        f"{local_path} does not exist"
                    )

            packages.add(Package(ECOSYSTEM.Npm, name, version, source=source))

        except (AttributeError, TypeError, ValueError) as e:
            _log.warning(f"Failed to resolve installed dependency {name}: {e}")

    return packages


def _load_lock_file_resolved_map(lock_file: Path) -> dict[tuple[str, str], str]:
    try:
        data = json.loads(lock_file.read_text())
    except (OSError, json.JSONDecodeError) as e:
        _log.debug(f"Could not read lock file {lock_file}: {e}")
        return {}

    result = {}

    for key, pkg_data in data.get("packages", {}).items():
        if key.startswith(NODE_MODULES_PREFIX):
            resolved = pkg_data.get("resolved", "")
            version = pkg_data.get("version", "")

            # Nested (non-hoisted) entries look like `node_modules/<parent>/node_modules/<child>`
            # Take the segment after the last `node_modules/` boundary
            if resolved and version:
                name = key.rpartition(NODE_MODULES_PREFIX)[2]
                result[(name, version)] = resolved

    return result
