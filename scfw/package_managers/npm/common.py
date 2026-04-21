"""
Common utilities for discovering installed npm packages.
"""

import json
import logging
from pathlib import Path
import subprocess
from typing import Optional

from scfw.ecosystem import ECOSYSTEM
from scfw.package import LocalPackageSource, Package, RemotePackageSource

_log = logging.getLogger(__name__)

_LOCAL_PACKAGE_SOURCE_PREFIX = "file:../"


def get_installed_packages(executable: Optional[str] = None, project_dir: Optional[Path] = None) -> set[Package]:
    """
        Return the set of packages installed as dependencies in a given `npm` project.

        Args:
            executable:
                An `Optional[str]` specifying the `npm` executable to use. If not provided,
                the executable is determined by the environment. The caller is responsible
                for ensuring that `executable` refers to a supported version of `npm`.
            project_dir:
                An `Optional[str]` specifying the target `npm` project directory. If not
                provided, the current working directory is used.

        Returns:
            A `set[Package]` representing unique packages installed as dependencies
            in the given in the given `npm` project.

        Raises:
            subprocess.CalledProcessError: Failed to list dependencies with `npm`.
            json.JSONDecodeError: Failed to decode installed packages report JSON.
        """
    def dependencies_to_packages(dependencies: dict[str, dict]) -> set[Package]:
        packages = set()

        for name, package_data in dependencies.items():
            try:
                if (package_dependencies := package_data.get("dependencies")):
                    packages |= dependencies_to_packages(package_dependencies)

                version = package_data["version"]

                if not (resolved := package_data.get("resolved")):
                    _log.info(f"No artifact source data found for installed dependency {name}")
                    packages.add(Package(ECOSYSTEM.Npm, name, version))
                    continue

                source: Optional[LocalPackageSource | RemotePackageSource] = None
                if resolved.startswith("http"):
                    source = RemotePackageSource(resolved)
                elif resolved.startswith(_LOCAL_PACKAGE_SOURCE_PREFIX):
                    source = LocalPackageSource(
                        Path(resolved[len(_LOCAL_PACKAGE_SOURCE_PREFIX):]).resolve(strict=True)
                    )

                packages.add(Package(ECOSYSTEM.Npm, name, version, source=source))

            except Exception as e:
                _log.warning(f"Failed to resolve installed dependency {name}: {e}")

        return packages

    npm_list_command = [executable if executable else "npm", "list", "--all", "--json"]

    npm_list = subprocess.run(npm_list_command, check=True, text=True, capture_output=True, cwd=project_dir)
    dependencies = json.loads(npm_list.stdout.strip()).get("dependencies")

    return dependencies_to_packages(dependencies) if dependencies else set()
