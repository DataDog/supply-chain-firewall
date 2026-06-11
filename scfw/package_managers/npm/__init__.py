"""
Provides a `PackageManager` representation of `npm`.
"""

import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
from typing import Optional

from packaging.version import InvalidVersion, parse as version_parse

from scfw.ecosystem import ECOSYSTEM
from scfw.package import LocalPackageSource, Package, RemotePackageSource
from scfw.package_manager import PackageManager, UnsupportedVersionError
from scfw.package_managers.npm.temp_project import FILE_URI_PREFIX, NODE_MODULES_PREFIX, TemporaryNpmProject

_log = logging.getLogger(__name__)

MIN_NPM_VERSION = version_parse("7.0.0")

# https://docs.npmjs.com/cli/v10/commands/npm-install
_INSTALL_COMMAND_ALIASES = {
    "install", "add", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall"
}


class Npm(PackageManager):
    """
    A `PackageManager` representation of `npm`.
    """
    def __init__(self, executable: Optional[str] = None):
        """
        Initialize a new `Npm` instance.

        Args:
            executable:
                An optional path in the local filesystem to the `npm` executable to use.
                If not provided, this value is determined by the current environment.

        Raises:
            RuntimeError: A valid executable could not be resolved.
        """
        executable = executable if executable else shutil.which(self.name())
        if not executable:
            raise RuntimeError("Failed to resolve local npm executable: is npm installed?")
        if not os.path.isfile(executable):
            raise RuntimeError(f"Path '{executable}' does not correspond to a regular file")

        self._executable = executable

    @classmethod
    def name(cls) -> str:
        """
        Return the token for invoking `npm` on the command line.
        """
        return "npm"

    @classmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the ecosystem of packages managed by `npm`.
        """
        return ECOSYSTEM.Npm

    def executable(self) -> str:
        """
        Return the local filesystem path to the underlying `npm` executable.
        """
        return self._executable

    def run_command(self, command: list[str]) -> int:
        """
        Run an `npm` command.

        Args:
            command: A `list[str]` containing an `npm` command to execute.

        Returns:
            An `int` return code describing the exit status of the executed `npm` command.

        Raises:
            ValueError: The given `command` is empty or not a valid `npm` command.
        """
        return subprocess.run(self._normalize_command(command)).returncode

    def resolve_install_targets(self, command: list[str]) -> list[Package]:
        """
        Resolve the installation targets of the given `npm` command.

        Args:
            command:
                A `list[str]` representing an `npm` command whose installation targets
                are to be resolved.

        Returns:
            A `list[Package]` representing the package targets that would be installed
            if `command` were run.

        Raises:
            ValueError: The given `command` is empty or not a valid `npm` command
            RuntimeError: Failed to resolve npm installation targets (with error detail)
            UnsupportedVersionError: The underlying `npm` executable is of an unsupported version.
        """
        if not command or command[0] != self.name():
            raise ValueError("Received empty or invalid npm command line")

        # For now, allow all non-`install` commands
        if not any(alias in command for alias in _INSTALL_COMMAND_ALIASES):
            return []

        self._check_version()

        # On supported versions, the presence of these options prevents the command from running
        if any(opt in command for opt in {"-h", "--help", "--dry-run", "--version"}):
            return []

        try:
            with TemporaryNpmProject(self._executable) as temp_project:
                return temp_project.resolve_install_command_targets(command)

        except Exception as e:
            raise RuntimeError(f"Failed to resolve npm installation targets: {e}")

    def list_installed_packages(self) -> list[Package]:
        """
        List all `npm` packages installed in the active `npm` environment.

        Returns:
            A `list[Package]` representing all `npm` packages installed in the active
            `npm` environment.

        Raises:
            RuntimeError: Failed to list installed packages or decode report JSON.
            UnsupportedVersionError: The underlying `npm` executable is of an unsupported version.
        """
        def load_lock_file_resolved_map(lock_file: Path) -> dict[tuple[str, str], str]:
            """
            Build a (name, version) -> resolved-URL map from a package-lock.json.

            Only entries under node_modules/ that carry both resolved and version
            fields are included. Keying by (name, version) keeps multiple versions
            of the same package distinct (e.g., a hoisted and a non-hoisted copy).
            Returns an empty dict if the file is missing or malformed.
            """
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
                    if resolved and version:
                        # Nested (non-hoisted) entries look like
                        # `node_modules/<parent>/node_modules/<child>` — take
                        # the segment after the last `node_modules/` boundary.
                        name = key.rpartition(NODE_MODULES_PREFIX)[2]
                        result[(name, version)] = resolved
            return result

        def dependencies_to_packages(
            dependencies: dict[str, dict],
            resolved_fallback: dict[tuple[str, str], str],
        ) -> set[Package]:
            packages = set()

            node_modules_path = Path.cwd() / "node_modules"

            for name, package_data in dependencies.items():
                try:
                    if not (version := package_data.get("version")):
                        # Skip the whole entry, including any `dependencies` subtree:
                        # npm list does not report children under an uninstalled parent.
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
                                    **load_lock_file_resolved_map(lock_file),
                                }
                        packages |= dependencies_to_packages(nested, nested_fallback)

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

        self._check_version()

        try:
            npm_list = subprocess.run(
                [self.executable(), "list", "--all", "--json"],
                check=True, text=True, capture_output=True,
            )

            dependencies = json.loads(npm_list.stdout.strip()).get("dependencies", {})
            if not isinstance(dependencies, dict):
                raise RuntimeError("Received malformed dependencies data from npm")

            resolved_fallback = load_lock_file_resolved_map(Path.cwd() / "package-lock.json")

            return list(dependencies_to_packages(dependencies, resolved_fallback))

        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to list npm installed packages")

        except json.JSONDecodeError:
            raise RuntimeError("Failed to decode installed package report JSON")

    def _check_version(self):
        """
        Check whether the underlying `npm` executable is of a supported version.

        Raises:
            UnsupportedVersionError: The underlying `npm` executable is of an unsupported version.
        """
        try:
            # All supported versions adhere to this format
            p = subprocess.run([self._executable, "--version"], check=True, text=True, capture_output=True)
            if version_parse(p.stdout.strip()) < MIN_NPM_VERSION:
                raise InvalidVersion

        except InvalidVersion:
            raise UnsupportedVersionError(f"npm before v{MIN_NPM_VERSION} is not supported")

    def _normalize_command(self, command: list[str]) -> list[str]:
        """
        Normalize an `npm` command.

        Args:
            command: A `list[str]` containing an `npm` command line.

        Returns:
            The equivalent but normalized form of `command` with the initial `npm`
            token replaced with the local filesystem path to `self.executable()`.

        Raises:
            ValueError: The given `command` is empty or not a valid `npm` command.
        """
        if not command:
            raise ValueError("Received empty npm command line")
        if command[0] != self.name():
            raise ValueError("Received invalid npm command line")

        return [self._executable] + command[1:]
