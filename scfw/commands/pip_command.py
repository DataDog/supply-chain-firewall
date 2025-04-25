"""
Defines a subclass of `PackageManagerCommand` for `pip` commands.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Optional

from packaging.version import InvalidVersion, Version, parse as version_parse

from scfw.command import PackageManagerCommand, UnsupportedVersionError
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget

_log = logging.getLogger(__name__)

MIN_PIP_VERSION = version_parse("22.2")

_UNSUPPORTED_PIP_VERSION = f"pip before v{MIN_PIP_VERSION} is not supported"


class PipCommand(PackageManagerCommand):
    """
    A representation of `pip` commands via the `PackageManagerCommand` interface.
    """
    def __init__(self, command: list[str], executable: Optional[str] = None):
        """
        Initialize a new `PipCommand`.

        Args:
            command: A `pip` command line.
            executable:
                Optional path to the executable to run the command.  Determined by the
                environment if not given.

        Raises:
            ValueError: An invalid `pip` command line was given.
            RuntimeError: A valid executable could not be resolved.
            UnsupportedVersionError:
                An unsupported version of `pip` was used to initialize a `PipCommand`.
        """
        def get_executable() -> Optional[str]:
            # Explicitly checking whether we are in a venv circumvents issues caused
            # by pyenv shims stomping the PATH with its own directories
            if (venv := os.environ.get("VIRTUAL_ENV")):
                return os.path.join(venv, "bin/python")
            else:
                return shutil.which("python")

        def get_pip_version(executable: str) -> Version:
            try:
                # All supported versions adhere to this format
                pip_version_command = [executable, "-m", "pip", "--version"]
                pip_version = subprocess.run(pip_version_command, check=True, text=True, capture_output=True)
                version_str = pip_version.stdout.split()[1]
                return version_parse(version_str)
            except IndexError:
                raise UnsupportedVersionError(_UNSUPPORTED_PIP_VERSION)
            except InvalidVersion:
                raise UnsupportedVersionError(_UNSUPPORTED_PIP_VERSION)

        if not command or command[0] != "pip":
            raise ValueError("Malformed pip command")

        executable = executable if executable else get_executable()
        if not executable:
            raise RuntimeError("Failed to resolve local Python executable")
        if not os.path.isfile(executable):
            raise RuntimeError(f"Path '{executable}' does not correspond to a regular file")

        if get_pip_version(executable) < MIN_PIP_VERSION:
            raise UnsupportedVersionError(_UNSUPPORTED_PIP_VERSION)

        self._command = command
        self._executable = executable

    @classmethod
    def name(cls) -> str:
        """
        Return the token for invoking `pip` on the command line.
        """
        return "pip"

    @classmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the package ecosystem of `pip` commands.
        """
        return ECOSYSTEM.PyPI

    def executable(self) -> str:
        """
        Query the Python executable for a `pip` command.
        """
        return self._executable

    def run(self):
        """
        Run a `pip` command.
        """
        subprocess.run([self._executable, "-m"] + self._command)

    def would_install(self) -> list[InstallTarget]:
        """
        Determine the package release targets a `pip` command would install if it were run.

        Returns:
            A `list[InstallTarget]` representing the package release targets the `pip` command
            would install if it were run.

        Raises:
            ValueError: The `pip` install report did not have the required format.
        """
        def report_to_install_targets(install_report: dict) -> InstallTarget:
            if not (metadata := install_report.get("metadata")):
                raise ValueError("Missing metadata for pip install target")
            if not (package := metadata.get("name")):
                raise ValueError("Missing name for pip install target")
            if not (version := metadata.get("version")):
                raise ValueError("Missing version for pip install target")
            return InstallTarget(ECOSYSTEM.PyPI, package, version)

        # pip only installs or upgrades packages via the `pip install` subcommand
        # If `install` is not present, the command is automatically safe to run
        # If `install` is present with any of the below options, a usage or error
        # message is printed or a dry-run install occurs: nothing will be installed
        if "install" not in self._command or any(opt in self._command for opt in {"-h", "--help", "--dry-run"}):
            return []

        # Otherwise, this is probably a "live" `pip install` command
        # To be certain, we would need to write a full parser for pip
        dry_run_command = [self._executable, "-m"] + self._command + ["--dry-run", "--quiet", "--report", "-"]
        try:
            dry_run = subprocess.run(dry_run_command, check=True, text=True, capture_output=True)
            install_report = json.loads(dry_run.stdout).get("install", [])
            return list(map(report_to_install_targets, install_report))
        except subprocess.CalledProcessError:
            # An error must have resulted from the given pip command
            # As nothing will be installed in this case, allow the command
            _log.info("The pip command encountered an error while collecting installation targets")
            return []
