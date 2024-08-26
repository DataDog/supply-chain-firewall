import subprocess
from typing import Optional

from scfw.command import PackageManagerCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget


class NpmCommand(PackageManagerCommand):
    """
    A representation of npm commands via the `PackageManagerCommand` interface.
    """
    def __init__(self, command: list[str], executable: Optional[str] = None):
        """
        Initialize a new `NpmCommand`.

        Args:
            self: The `NpmCommand` to be initialized.
            command: The npm command line as provided to the supply-chain firewall.
            `executable`: An optional path to the npm executable to use to run the command.
        """
        assert command and command[0] == "npm", "Malformed npm command"
        self._command = command

        if executable:
            self._command[0] = executable

    def run(self):
        """
        Run an npm command.

        Args:
            self: The `NpmCommand` to run.
        """
        subprocess.run(self._command)

    def would_install(self) -> list[InstallTarget]:
        """
        Determine the list of packages an npm command would install if it were run.

        Args:
            self: The `NpmCommand` to inspect.

        Returns:
            The list of packages the npm command would install if it were run.
        """
        def is_add_line(line: str) -> bool:
            return line.startswith("add") and not line.startswith("added")

        def line_to_install_target(line: str) -> InstallTarget:
            assert len(line.split()) == 3, "Failed to parse npm install target"
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
