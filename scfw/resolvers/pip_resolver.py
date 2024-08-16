import subprocess
import sys

from scfw.ecosystem import ECOSYSTEM
from scfw.resolver import InstallTargetsResolver
from scfw.target import InstallTarget


class PipInstallTargetsResolver(InstallTargetsResolver):
    def resolve_targets(self, pip_install_command: list[str]) -> list[InstallTarget]:
        def str_to_install_target(target_str: str) -> InstallTarget:
            package, _, version = target_str.rpartition('-')
            if version == target_str:
                raise Exception("Failed to parse pip install target")
            
            return InstallTarget(ECOSYSTEM.PIP, package, version)

        # TODO: Allow more flexibility of form in the `pip install` command
        if not pip_install_command:
            return []
        if pip_install_command[:2] != ["pip", "install"]:
            raise Exception("Invalid pip install command")
        
        dry_run_command = [sys.executable, "-m", "pip", "install", "--dry-run"]
        dry_run_command.extend(pip_install_command[2:])

        dry_run = subprocess.run(dry_run_command, text=True, check=True, capture_output=True)
        for line in dry_run.stdout.split('\n'):
            if line.startswith("Would install"):
                return list(map(str_to_install_target, line.split()[2:]))
        
        return []
