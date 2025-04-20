"""
Defines a subclass of `PackageManagerCommand` for `poetry` commands.
"""

import logging
import os
import re
import shutil
import subprocess
from typing import Optional

from scfw.command import PackageManagerCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget

_log = logging.getLogger(__name__)


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
        """
        if not command or command[0] != self.name():
            raise ValueError("Malformed Poetry command")

        executable = executable if executable else shutil.which(self.name())
        if not executable:
            raise RuntimeError("Failed to resolve local Poetry executable")
        if not os.path.isfile(executable):
            raise RuntimeError(f"Path '{executable}' does not correspond to a regular file")

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
            # TODO(ikretz): Support more complex version specifications
            old_version, sep, new_version = version_spec.partition(" -> ")
            return new_version if sep else old_version

        def is_dependency_line(line: str) -> bool:
            return any(opt in line for opt in {"Installing", "Upgrading", "Downgrading"}) and "Skipped" not in line

        def line_to_install_target(line: str) -> InstallTarget:
            pattern = r"- (Installing|Upgrading|Downgrading) (.*) \((.*)\)"
            match = re.search(pattern, line.strip())
            return InstallTarget(ECOSYSTEM.PyPI, match.group(2), get_target_version(match.group(3)))

        # For now, automatically allow all non-`add` commands
        if "add" not in self._command:
            return []

        # The presence of these options prevent the add command from running
        if any(opt in self._command for opt in {"-h", "--help", "--dry-run"}):
            return []

        try:
            # Compute installation targets: new dependencies and upgrades/downgrades of existing ones
            dry_run_command = self._command + ["--dry-run"]
            dry_run = subprocess.run(dry_run_command, check=True, text=True, capture_output=True)
            return list(map(line_to_install_target, filter(is_dependency_line, dry_run.stdout.split('\n'))))
        except subprocess.CalledProcessError:
            # An erroring command does not install anything
            _log.info("The Poetry command encountered an error while collecting installation targets")
            return []
