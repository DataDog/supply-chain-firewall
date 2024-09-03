"""
Defines a subclass of `PackageManagerCommand` for `npm` commands.
"""

import subprocess
from typing import Optional

from scfw.command import PackageManagerCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget


class NpmCommand(PackageManagerCommand):
    """
    A representation of `npm` commands via the `PackageManagerCommand` interface.
    """
    def __init__(self, command: list[str], executable: Optional[str] = None):
        """
        Initialize a new `NpmCommand`.

        Args:
            command: An `npm` command line.
            executable:
                Optional path to the executable to run the command.  Determined by the
                environment if not given.

        Raises:
            ValueError: An invalid `npm` command was given.
        """
        if not command or command[0] != "npm":
            raise ValueError("Malformed npm command")
        self._command = command

        if executable:
            self._command[0] = executable

    def run(self):
        """
        Run an `npm` command.
        """
        subprocess.run(self._command)

    def would_install(self) -> list[InstallTarget]:
        """
        Determine the list of packages an `npm` command would install if it were run.

        Returns:
            A `list[InstallTarget]` representing the packages the `npm` command would
            install if it were run.

        Raises:
            ValueError: The `npm` dry-run output does not have the expected format.
        """
        def is_add_line(line: str) -> bool:
            return line.startswith("add") and not line.startswith("added")

        def line_to_install_target(line: str) -> InstallTarget:
            if len(line.split()) != 3:
                raise ValueError("Failed to parse npm install target")
            _, package, version = line.split()
            return InstallTarget(ECOSYSTEM.NPM, package, version)

        # If any of the below options are present, a help message is printed or
        # a dry-run of an installish action occurs: nothing will be installed
        if any(opt in self._command for opt in {"-h", "--help", "--dry-run"}):
            return []

        dry_run_command = self._command + ["--dry-run"]
        try:
            dry_run = subprocess.run(dry_run_command, check=True, text=True, capture_output=True)
            return list(map(line_to_install_target, filter(is_add_line, dry_run.stdout.split('\n'))))
        except subprocess.CalledProcessError:
            # An error must have resulted from the given npm command
            # As nothing will be installed in this case, allow the command
            return []
