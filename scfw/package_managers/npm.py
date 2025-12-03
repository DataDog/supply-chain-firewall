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

from packaging.version import InvalidVersion, Version, parse as version_parse

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_manager import PackageManager, UnsupportedVersionError

_log = logging.getLogger(__name__)

MIN_NPM_VERSION = version_parse("7.0.0")


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
            ValueError:
                1) The given `command` is empty or not a valid `npm` command, or 2) failed to parse
                an installation target.
            UnsupportedVersionError: The underlying `npm` executable is of an unsupported version.
        """
        def is_install_command(command: list[str]) -> bool:
            # https://docs.npmjs.com/cli/v10/commands/npm-install
            install_aliases = {
                "install", "add", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall"
            }
            return any(alias in command for alias in install_aliases)

        def detect_lockfile() -> Optional[Path]:
            npm_prefix_command = self._normalize_command(["npm", "prefix"])
            npm_prefix = subprocess.run(npm_prefix_command, check=True, text=True, capture_output=True).stdout.strip()
            if not npm_prefix:
                _log.debug("'npm prefix' command returned empty output")
                return None

            lockfile_path = Path(npm_prefix) / "package-lock.json"
            if not lockfile_path.is_file():
                _log.debug("No package-lock.json file found in current project root")
                return None

            return lockfile_path

        def extract_target_handles(dry_run_log: list[str]) -> list[str]:
            target_handles = []

            # TODO(ikretz): All supported npm versions adhere to this format
            for line in dry_run_log:
                line_tokens = line.split()

                if line_tokens[1] in {"sill", "silly"} and line_tokens[2] in {"ADD", "CHANGE"}:
                    target_handles.append(line_tokens[3])

            return target_handles

        def extract_placed_dependencies(dry_run_log: list[str]) -> list[Package]:
            placed_dependencies = []

            # All supported npm versions adhere to this format
            for line in dry_run_log:
                line_tokens = line.split()

                if line_tokens[2] != "placeDep":
                    continue
                target_spec = line_tokens[4]

                name, sep, version = target_spec.rpartition('@')
                if not (name and sep):
                    raise ValueError(f"Failed to parse npm installation target specification '{target_spec}'")

                placed_dependencies.append(Package(ECOSYSTEM.Npm, name, version))

            return placed_dependencies

        # TODO(ikretz): Test and validate this function
        def extract_target_name(target_handle: str) -> str:
            return target_handle.rpartition("node_modules/")[2]

        def match_to_placed_dependency(placed_dependencies: list[Package], target_name: str) -> Optional[int]:
            return next((i for i, package in enumerate(placed_dependencies) if package.name == target_name), None)

        command = self._normalize_command(command)

        # For now, allow all non-`install` commands
        if not is_install_command(command):
            return []

        self._check_version()

        # On supported versions, the presence of these options prevents the command from running
        if any(opt in command for opt in {"-h", "--help", "--dry-run"}):
            return []

        try:
            dry_run_command = command + ["--dry-run", "--loglevel", "silly"]
            dry_run = subprocess.run(dry_run_command, check=True, text=True, capture_output=True)
            dry_run_log = dry_run.stderr.strip().split('\n')

            # Each target handle corresponds to a (possibly duplicated) installation target
            target_handles = extract_target_handles(dry_run_log)
            if not target_handles:
                return []

            install_targets = set()
            placed_dependencies = extract_placed_dependencies(dry_run_log)

            # Read `package-lock.json`, if it exists
            lockfile = {}
            try:
                if (lockfile_path := detect_lockfile()):
                    with open(lockfile_path) as f:
                        lockfile = json.load(f)
            except Exception as e:
                _log.warning(f"Failed to read package lockfile: {e}")

            while target_handles:
                target_handle = target_handles.pop()
                target_name = extract_target_name(target_handle)

                if (match_index := match_to_placed_dependency(placed_dependencies, target_name)) is not None:
                    placed_dependency = placed_dependencies.pop(match_index)

                    _log.debug(
                        f"Matched npm installation target '{target_name}' to placed dependency {placed_dependency}"
                    )
                    install_targets.add(placed_dependency)

                # TODO(ikretz): Verify which package-lock.json versions fulfill this assumed structure
                elif (lockfile_entry := lockfile.get("packages", {}).get(target_handle)):
                    _log.debug(
                        f"Matched npm installation target '{target_name}' to lockfile file entry '{target_handle}'"
                    )

                    target_version = lockfile_entry.get("version")
                    if not target_version:
                        raise RuntimeError(f"Malformed lockfile entry for npm installation target '{target_name}'")

                    install_targets.add(Package(ECOSYSTEM.Npm, name=target_name, version=target_version))

                else:
                    raise RuntimeError(
                        f"Failed to resolve npm installation target '{target_name}' to a precise target version"
                    )

            if placed_dependencies:
                raise RuntimeError(
                    f"Failed to match all placed dependencies to npm installation targets: {placed_dependencies}"
                )

            return list(install_targets)

        except subprocess.CalledProcessError:
            # An erroring command does not install anything
            _log.info("The input npm command results in error: nothing will be installed")
            return []

    def list_installed_packages(self) -> list[Package]:
        """
        List all `npm` packages installed in the active `npm` environment.

        Returns:
            A `list[Package]` representing all `npm` packages installed in the active
            `npm` environment.

        Raises:
            RuntimeError: Failed to list installed packages or decode report JSON.
            ValueError: Encountered a malformed report for an installed package.
            UnsupportedVersionError: The underlying `npm` executable is of an unsupported version.
        """
        def dependencies_to_packages(dependencies: dict[str, dict]) -> set[Package]:
            packages = set()

            for name, package_data in dependencies.items():
                if (package_dependencies := package_data.get("dependencies")):
                    packages |= dependencies_to_packages(package_dependencies)
                packages.add(Package(ECOSYSTEM.Npm, name, package_data["version"]))

            return packages

        self._check_version()

        try:
            npm_list_command = self._normalize_command(["npm", "list", "--all", "--json"])
            npm_list = subprocess.run(npm_list_command, check=True, text=True, capture_output=True)
            dependencies = json.loads(npm_list.stdout.strip()).get("dependencies")
            return list(dependencies_to_packages(dependencies)) if dependencies else []

        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to list npm installed packages")

        except json.JSONDecodeError:
            raise RuntimeError("Failed to decode installed package report JSON")

        except KeyError:
            raise ValueError("Malformed installed package report")

    def _check_version(self):
        """
        Check whether the underlying `npm` executable is of a supported version.

        Raises:
            UnsupportedVersionError: The underlying `npm` executable is of an unsupported version.
        """
        def get_npm_version(executable: str) -> Optional[Version]:
            try:
                # All supported versions adhere to this format
                npm_version = subprocess.run([executable, "--version"], check=True, text=True, capture_output=True)
                return version_parse(npm_version.stdout.strip())
            except InvalidVersion:
                return None

        npm_version = get_npm_version(self._executable)
        if not npm_version or npm_version < MIN_NPM_VERSION:
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
