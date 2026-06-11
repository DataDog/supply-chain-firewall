"""
Provides a `PackageManager` representation of `npm`.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Optional

from packaging.version import InvalidVersion, parse as version_parse

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_manager import PackageManager, UnsupportedVersionError
from scfw.package_managers.npm import installed
from scfw.package_managers.npm.temp_project import TemporaryNpmProject

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
        self._check_version()

        try:
            return installed.list_installed_packages(self.executable())

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
