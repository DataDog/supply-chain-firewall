"""
Defines a subclass of `PackageManagerCommand` for `poetry` commands.
"""

import logging
import os
import re
import shutil
import subprocess
from typing import Optional

from packaging.version import InvalidVersion, Version, parse as version_parse

from scfw.command import PackageManagerCommand, UnsupportedVersionError
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget

_log = logging.getLogger(__name__)

MIN_POETRY_VERSION = version_parse("1.7.0")

INSPECTED_SUBCOMMANDS = {"add", "install", "sync", "update"}


class PoetryCommand(PackageManagerCommand):
    """
    A representation of `poetry` commands via the `PackageManagerCommand` interface.
    """
    def __init__(self, command: list[str], executable: Optional[str] = None):
        """
        Initialize a new `PoetryCommand`.

        Args:
            command: A `poetry` command line.
            executable:
                Optional path to the executable to run the command.  Determined by the
                environment if not given.

        Raises:
            ValueError: An invalid `poetry` command line was given.
            RuntimeError: A valid executable could not be resolved.
            UnsupportedVersionError:
                An unsupported version of Poetry was used to initialize a `PoetryCommand`.
        """
        def get_poetry_version(executable: str) -> Version:
            try:
                # All supported versions adhere to this format
                poetry_version = subprocess.run([executable, "--version"], check=True, text=True, capture_output=True)
                if (match := re.search(r"Poetry \(version (.*)\)", poetry_version.stdout.strip())):
                    return version_parse(match.group(1))
                raise UnsupportedVersionError("Failed to parse Poetry version output")
            except InvalidVersion:
                raise UnsupportedVersionError("Failed to parse Poetry version number")

        if not command or command[0] != self.name():
            raise ValueError("Malformed Poetry command")

        executable = executable if executable else shutil.which(self.name())
        if not executable:
            raise RuntimeError("Failed to resolve local Poetry executable")
        if not os.path.isfile(executable):
            raise RuntimeError(f"Path '{executable}' does not correspond to a regular file")

        if get_poetry_version(executable) < MIN_POETRY_VERSION:
            raise UnsupportedVersionError(f"Poetry before v{MIN_POETRY_VERSION} is not supported")

        self._command = command.copy()
        self._command[0] = executable

    @classmethod
    def name(cls) -> str:
        """
        Return the token for invoking `poetry` on the command line.
        """
        return "poetry"

    @classmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the package ecosystem of `poetry` commands.
        """
        return ECOSYSTEM.PyPI

    def executable(self) -> str:
        """
        Query the executable for a `poetry` command.
        """
        return self._command[0]

    def run(self):
        """
        Run a `poetry` command.
        """
        subprocess.run(self._command)

    def would_install(self) -> list[InstallTarget]:
        """
        Determine the package release targets a `poetry` command would install if
        it were run.

        Returns:
            A `list[InstallTarget]` representing the packages release targets the
            `poetry` command would install if it were run.
        """
        def get_target_version(version_spec: str) -> str:
            _, arrow, new_version = version_spec.partition(" -> ")
            version, _, _ = version_spec.partition(' ')
            return get_target_version(new_version) if arrow else version

        def line_to_install_target(line: str) -> Optional[InstallTarget]:
            # All supported versions adhere to this format
            pattern = r"(Installing|Updating|Downgrading) (?:the current project: )?(.*) \((.*)\)"
            if "Skipped" not in line and (match := re.search(pattern, line.strip())):
                return InstallTarget(self.ecosystem(), match.group(2), get_target_version(match.group(3)))
            return None

        if not any(subcommand in self._command for subcommand in INSPECTED_SUBCOMMANDS):
            return []

        # The presence of these options prevent the add command from running
        if any(opt in self._command for opt in {"-V", "--version", "-h", "--help", "--dry-run"}):
            return []

        try:
            # Compute installation targets: new dependencies and updates/downgrades of existing ones
            dry_run_command = self._command + ["--dry-run"]
            dry_run = subprocess.run(dry_run_command, check=True, text=True, capture_output=True)
            return list(filter(None, map(line_to_install_target, dry_run.stdout.split('\n'))))
        except subprocess.CalledProcessError:
            # An erroring command does not install anything
            _log.info("The Poetry command encountered an error while collecting installation targets")
            return []
