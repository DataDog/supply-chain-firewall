import json
import os
import subprocess
import sys
from typing import Optional

from scfw.command import PackageManagerCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget


class PipCommand(PackageManagerCommand):
    def __init__(self, command: list[str], executable: Optional[str] = None):
        # TODO: Deal with the fact that pip commands can specify the executable to use
        def get_executable() -> str:
            if (venv := os.environ.get("VIRTUAL_ENV")):
                return os.path.join(venv, "bin/python")
            else:
                return sys.executable

        assert command and command[0] == "pip", "Malformed pip command"
        self._command = command

        # TODO: Validate the given executable path
        self._executable = executable if executable else get_executable()

    def run(self):
        subprocess.run([self._executable, "-m"] + self._command)

    def would_install(self) -> list[InstallTarget]:
        def report_to_install_targets(install_report: dict) -> InstallTarget:
            assert (metadata := install_report.get("metadata")), "Missing metadata for pip install target"
            assert (package := metadata.get("name")), "Missing name for pip install target"
            assert (version := metadata.get("version")), "Missing version for pip install target"
            return InstallTarget(ECOSYSTEM.PIP, package, version)

        # pip only installs or upgrades packages via the `pip install` subcommand
        # If `install` is not present, the command is automatically safe to run
        # If `install` is present with any of the below options, a usage or error
        # message is printed or a dry-run install occurs: nothing will be installed
        if not "install" in self._command or any(opt in self._command for opt in {"-h", "--help", "--dry-run"}):
            return []

        # TODO: Make use of the `--report` option of `pip install`
        # Otherwise, this is probably a "live" `pip install` command
        # To be certain, we would need to write a full parser for pip
        dry_run_command = [self._executable, "-m"] + self._command + ["--dry-run", "--quiet", "--report", "-"]
        dry_run = subprocess.run(dry_run_command, text=True, check=True, capture_output=True)
        install_report = json.loads(dry_run.stdout).get("install", [])

        return list(map(report_to_install_targets, install_report))