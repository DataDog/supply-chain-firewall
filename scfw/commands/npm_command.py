import subprocess
from typing import Optional

from scfw.command import PackageManagerCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget


class NpmCommand(PackageManagerCommand):
    def __init__(self, command: list[str], executable: Optional[str] = None):
        assert command and command[0] == "npm", "Malformed npm command"
        self._command = command

        # TODO: Validate the given executable path
        if executable:
            self._command[0] = executable

    def run(self):
        subprocess.run(self._command)

    def would_install(self) -> list[InstallTarget]:
        def line_to_install_target(line: str) -> Optional[InstallTarget]:
            # TODO: Determine whether these "add" lines always have this format
            # TODO: Determine whether all dry runs identify install targets this way
            if line.startswith("add") and not line.startswith("added"):
                assert len(line.split()) == 3, "Failed to parse npm install target"
                _, package, version = line.split()
                return InstallTarget(ECOSYSTEM.NPM, package, version)
            else:
                return None

        # If any of the below options are present, a help message is printed or
        # a dry-run of an installish action occurs: nothing will be installed
        if any(opt in self._command for opt in {"-h", "--help", "--dry-run"}):
            return []

        dry_run_command = self._command + ["--dry-run"]
        dry_run = subprocess.run(dry_run_command, text=True, check=True, capture_output=True)

        return list(filter(lambda x: x is not None, map(line_to_install_target, dry_run.stdout.split('\n'))))
