import subprocess
from typing import Optional

from scfw.command import PackageManagerCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget


class NpmCommand(PackageManagerCommand):
    def __init__(self, command: list[str], executable: Optional[str] = None):
        if len(command) < 3 or command[:2] != ["npm", "install"]:
            raise Exception("Unsupported npm command")
        self._command = command

        # TODO: Validate the given executable path
        if executable:
            self._command[0] = executable

    def run(self):
        subprocess.run(self._command)

    def would_install(self) -> list[InstallTarget]:
        targets = []

        dry_run_command = ["npm", "install", "--dry-run"]
        dry_run_command.extend(self._command[2:])

        dry_run = subprocess.run(dry_run_command, text=True, check=True, capture_output=True)
        for line in dry_run.stdout.split('\n'):
            if line.startswith("add") and not line.startswith("added"):
                # TODO: Determine whether these "add" lines always have this format
                _, package, version = line.split()
                targets.append(InstallTarget(ECOSYSTEM.NPM, package, version))

        return targets
