import subprocess

from scfw.ecosystem import ECOSYSTEM
from scfw.resolver import InstallTargetsResolver
from scfw.target import InstallTarget


class NpmInstallTargetsResolver(InstallTargetsResolver):
    def resolve_targets(self, npm_install_command: list[str]) -> list[InstallTarget]:
        targets = []

        # TODO: Allow more flexibility of form in the `npm install` command
        if not npm_install_command:
            return []
        if npm_install_command[:2] != ["npm", "install"]:
            raise Exception("Invalid npm install command")

        dry_run_command = ["npm", "install", "--dry-run"]
        dry_run_command.extend(npm_install_command[2:])

        dry_run = subprocess.run(dry_run_command, text=True, check=True, capture_output=True)
        for line in dry_run.stdout.split('\n'):
            if line.startswith("add") and not line.startswith("added"):
                # TODO: Determine whether these "add" lines always have this format
                _, package, version = line.split()
                targets.append(InstallTarget(ECOSYSTEM.NPM, package, version))

        return targets
