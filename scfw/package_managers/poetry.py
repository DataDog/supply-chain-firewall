"""
Provides a `PackageManager` representation of `poetry`.
"""

import logging
import os
import re
import shutil
import subprocess
from typing import Optional

from packaging.version import InvalidVersion, Version, parse as version_parse

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_manager import PackageManager, UnsupportedVersionError

_log = logging.getLogger(__name__)

MIN_POETRY_VERSION = version_parse("1.7.0")

INSPECTED_SUBCOMMANDS = {"add", "install", "sync", "update"}


class Poetry(PackageManager):
    """
    A `PackageManager` representation of `poetry`.
    """
    def __init__(self, executable: Optional[str] = None):
        """
        Initialize a new `Poetry` instance.

        Args:
            executable:
                An optional path in the local filesystem to the `poetry` executable to use.
                If not provided, this value is determined by the current environment.

        Raises:
            RuntimeError: A valid executable could not be resolved.
            UnsupportedVersionError: The underlying `poetry` executable is of an unsupported version.
        """
        def get_poetry_version(executable: str) -> Optional[Version]:
            try:
                # All supported versions adhere to this format
                poetry_version = subprocess.run([executable, "--version"], check=True, text=True, capture_output=True)
                match = re.search(r"Poetry \(version (.*)\)", poetry_version.stdout.strip())
                return version_parse(match.group(1)) if match else None
            except InvalidVersion:
                return None

        executable = executable if executable else shutil.which(self.name())
        if not executable:
            raise RuntimeError("Failed to resolve local poetry executable")
        if not os.path.isfile(executable):
            raise RuntimeError(f"Path '{executable}' does not correspond to a regular file")

        poetry_version = get_poetry_version(executable)
        if not poetry_version or poetry_version < MIN_POETRY_VERSION:
            raise UnsupportedVersionError(f"Poetry before v{MIN_POETRY_VERSION} is not supported")

        self._executable = executable

    @classmethod
    def name(cls) -> str:
        """
        Return the token for invoking `poetry` on the command line.
        """
        return "poetry"

    @classmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the ecosystem of packages managed by `poetry`.
        """
        return ECOSYSTEM.PyPI

    def executable(self) -> str:
        """
        Return the local filesystem path to the underlying `poetry` executable.
        """
        return self._executable

    def run_command(self, command: list[str]):
        """
        Run a `poetry` command.

        Args:
            command: A `list[str]` containing a `poetry` command to execute.

        Raises:
            ValueError: The given `command` is empty or not a valid `poetry` command.
        """
        subprocess.run(self._normalize_command(command))

    def resolve_install_targets(self, command: list[str]) -> list[Package]:
        """
        Resolve the installation targets of the given `poetry` command.

        Args:
            command:
                A `list[str]` representing a `poetry` command whose installation targets
                are to be resolved.

        Returns:
            A `list[Package]` representing the package targets that would be installed
            if `command` were run.

        Raises:
            ValueError: The given `command` is empty or not a valid `poetry` command.
        """
        def get_target_version(version_spec: str) -> str:
            _, arrow, new_version = version_spec.partition(" -> ")
            version, _, _ = version_spec.partition(' ')
            return get_target_version(new_version) if arrow else version

        def line_to_package(line: str) -> Optional[Package]:
            # All supported versions adhere to this format
            pattern = r"(Installing|Updating|Downgrading) (?:the current project: )?(.*) \((.*)\)"
            if "Skipped" not in line and (match := re.search(pattern, line.strip())):
                return Package(self.ecosystem(), match.group(2), get_target_version(match.group(3)))
            return None

        command = self._normalize_command(command)

        if not any(subcommand in command for subcommand in INSPECTED_SUBCOMMANDS):
            return []

        # The presence of these options prevents the command from running
        if any(opt in command for opt in {"-V", "--version", "-h", "--help", "--dry-run"}):
            return []

        try:
            # Compute installation targets: new dependencies and updates/downgrades of existing ones
            dry_run = subprocess.run(command + ["--dry-run"], check=True, text=True, capture_output=True)
            return list(filter(None, map(line_to_package, dry_run.stdout.split('\n'))))
        except subprocess.CalledProcessError:
            # An erroring command does not install anything
            _log.info("Encountered an error while resolving poetry installation targets")
            return []

    def list_installed_packages(self) -> list[Package]:
        """
        List all `PyPI` packages installed in the active `poetry` environment.

        Returns:
            A `list[Package]` representing all `PyPI` packages installed in the active
            `poetry` environment.

        Raises:
            RuntimeError: Failed to list installed packages.
            ValueError: Malformed installed package report.
        """
        def line_to_package(line: str) -> Package:
            tokens = line.split()
            return Package(ECOSYSTEM.PyPI, tokens[0], tokens[1])

        try:
            poetry_show_command = self._normalize_command(["poetry", "show", "--all"])
            poetry_show = subprocess.run(poetry_show_command, check=True, text=True, capture_output=True)
            installed_report = poetry_show.stdout.strip()
            return list(map(line_to_package, installed_report.split('\n'))) if installed_report else []

        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to list poetry installed packages")

        except IndexError:
            raise ValueError("Malformed installed package report")

    def _normalize_command(self, command: list[str]) -> list[str]:
        """
        Normalize a `poetry` command.

        Args:
            command: A `list[str]` containing a `poetry` command line.

        Returns:
            The equivalent but normalized form of `command` with the initial `poetry`
            token replaced with the local filesystem path to `self.executable()`.

        Raises:
            ValueError: The given `command` is empty or not a valid `poetry` command.
        """
        if not command:
            raise ValueError("Received empty poetry command line")
        if command[0] != self.name():
            raise ValueError("Received invalid poetry command line")

        return [self._executable] + command[1:]
