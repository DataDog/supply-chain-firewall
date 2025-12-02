"""
Provides a `PackageManager` representation of `npm`.
"""

import json
import logging
import os
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

        def is_add_target_line(line: str) -> bool:
            # The "add" output lines note the command's installation targets
            return line.startswith("add") and not line.startswith("added")

        def line_to_package(line: str) -> Package:
            # The installation target name and version are always the second
            # and third tokens, respectively, of its "add" line
            tokens = line.split()
            return Package(ECOSYSTEM.Npm, name=tokens[1], version=tokens[2])

        command = self._normalize_command(command)

        # For now, allow all non-`install` commands
        if not is_install_command(command):
            return []

        self._check_version()

        # On supported versions, the presence of these options prevents the command from running
        if any(opt in command for opt in {"-h", "--help", "--dry-run"}):
            return []

        try:
            dry_run_command = command + ["--dry-run"]
            dry_run = subprocess.run(dry_run_command, check=True, text=True, capture_output=True)
            return list(map(line_to_package, filter(is_add_target_line, dry_run.stdout.strip().split('\n'))))

        except subprocess.CalledProcessError:
            # An erroring command does not install anything
            _log.info("Encountered an error while resolving npm installation targets")
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
