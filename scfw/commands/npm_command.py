import subprocess
from typing import Optional

from scfw.command import PackageManagerCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget

# The npm subcommands (and their aliases) that can install or upgrade packages
NPM_INSTALLISH_SUBCOMMANDS = [
    # npm audit
    "audit",
    # npm ci
    "ci",
    "clean-install",
    "ic",
    "install-clean",
    "isntall-clean",
    # npm dedupe
    "dedupe",
    "ddp",
    # npm install
    "install",
    "add",
    "i",
    "in",
    "ins",
    "inst",
    "insta",
    "instal",
    "isnt",
    "isnta",
    "isntal",
    "isntall",
    # npm install-ci-test
    "install-ci-test",
    "cit",
    "clean-install-test",
    "sit",
    # npm install-test
    "install-test",
    "it",
    # npm update
    "update",
    "up",
    "upgrade",
    "udpate"
]


class NpmCommand(PackageManagerCommand):
    def __init__(self, command: list[str], executable: Optional[str] = None):
        def find_install_subcommand() -> Optional[int]:
            index = None
            for subcommand in NPM_INSTALLISH_SUBCOMMANDS:
                try:
                    index = command.index(subcommand) + 1
                    break
                except ValueError:
                    pass

            return index

        assert command and command[0] == "npm", "Malformed npm command"
        self._command = command

        # TODO: Validate the given executable path
        if executable:
            self._command[0] = executable

        # If none of the above subcommands are present, the command is safe to run
        # If one of these subcommands is present with any of the below options, a
        # help message or a dry-run installish action occurs: nothing will be installed
        install_subcommand = find_install_subcommand()
        if not install_subcommand or any(opt in command for opt in {"-h", "--help", "--dry-run"}):
            self._install_subcommand = None
        else:
            # Otherwise, this is probably a "live" installish command
            # Save the index of the first argument to the install subcommand
            self._install_subcommand = install_subcommand

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

        if not self._install_subcommand:
            return []

        # Inserting the `--dry-run` flag at the opening of the `install` subcommand
        dry_run_command = (
            self._command[:self._install_subcommand] + ["--dry-run"] + self._command[self._install_subcommand:]
        )
        dry_run = subprocess.run(dry_run_command, text=True, check=True, capture_output=True)

        return list(filter(lambda x: x is not None, map(line_to_install_target, dry_run.stdout.split('\n'))))
