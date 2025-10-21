"""
Defines a subclass of `PackageManagerCommand` for `go` commands.
"""

import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Optional

from packaging.version import InvalidVersion, Version, parse as version_parse

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_manager import PackageManager, UnsupportedVersionError
from scfw.package_managers.go.temp_env import TempGoEnvironment

_log = logging.getLogger(__name__)

MIN_GO_VERSION = version_parse("1.17.0")

INSPECTED_SUBCOMMANDS = {"build", "generate", "get", "install", "mod", "run"}

INSPECTED_MOD_COMMANDS = {"download", "graph", "tidy", "verify", "why"}

DRY_RUN_PROJECT = "localhost/dry_run"


class Go(PackageManager):
    """
    A `PackageManager` representation of `go`.
    """
    def __init__(self, executable: Optional[str] = None):
        """
        Initialize a new `Go` instance.

        Args:
            executable:
                An optional path in the local filesystem to the `go` executable to use.
                If not provided, this value is determined by the current environment.

        Raises:
            RuntimeError: A valid executable could not be resolved.
        """
        executable = executable if executable else shutil.which(self.name())
        if not executable:
            raise RuntimeError("Failed to resolve local Go executable: is Go installed?")
        if not os.path.isfile(executable):
            raise RuntimeError(f"Path '{executable}' does not correspond to a regular file")

        self._executable = executable

    @classmethod
    def name(cls) -> str:
        """
        Return the token for invoking `go` on the command line.
        """
        return "go"

    @classmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the package ecosystem of `go` commands.
        """
        return ECOSYSTEM.Go

    def executable(self) -> str:
        """
        Query the executable for a `go` command.
        """
        return self._executable

    def run_command(self, command: list[str]) -> int:
        """
        Run a `go` command.

        Args:
            command: A `list[str]` containing a `go` command to execute.

        Returns:
            An `int` return code describing the exit status of the executed `go` command.

        Raises:
            ValueError: The given `command` is empty or not a valid `go` command.
        """
        return subprocess.run(self._normalize_command(command)).returncode

    def resolve_install_targets(self, command: list[str]) -> list[Package]:
        """
        Resolve the installation targets of the given `go` command.

        Args:
            command:
                A `list[str]` representing a `go` command whose installation targets
                are to be resolved.

        Returns:
            A `list[Package]` representing the package targets that would be installed
            if `command` were run.

        Raises:
            ValueError: The given `command` is empty or not a valid `go` command.
            UnsupportedVersionError: The underlying `go` executable is of an unsupported version.
            GoModNotFoundError: No `go.mod` file was found for the given `go` command.
        """
        def line_to_package(line: str) -> Optional[Package]:
            # All supported versions adhere to this format
            components = line.strip().split()
            if len(components) == 2 and components[0] != DRY_RUN_PROJECT:
                return Package(self.ecosystem(), components[0], components[1])
            return None

        command = self._normalize_command(command)

        if not any(subcommand in command for subcommand in INSPECTED_SUBCOMMANDS):
            return []

        if len(command) > 2 and command[1] == "mod" and not command[2] in INSPECTED_MOD_COMMANDS:
            return []

        self._check_version()

        # The presence of these options prevent the add command from running
        if any(opt in command for opt in {"-h", "-help"}):
            return []

        try:
            # Compute installation targets: new dependencies and updates/downgrades of existing ones
            local_packages = []
            remote_packages = []

            is_tidy = len(command) > 2 and command[1] == "mod" and command[2] == "tidy"
            for param in command[2 if not is_tidy else 3:]:
                if not param.startswith("-"):
                    # TODO: Handle packages with envvars?
                    is_local = Path(param).exists()
                    if is_local or len(param.split("/")) == 1:
                        local_packages.append(param)
                    else:
                        remote_packages.append(param)

            with TempGoEnvironment(self.executable()) as tmp:
                packages = set()
                if len(remote_packages) > 0:
                    # Create a temporary project and retrieve what would be installed in it.
                    tmp.run(["mod", "init", DRY_RUN_PROJECT])
                    tmp.run(["get"] + remote_packages)
                    dry_run = tmp.run(["list", "-m", "all"])
                    packages.update(set(filter(None, map(line_to_package, dry_run.stdout.split('\n')))))

                if is_tidy:
                    tmp.duplicate_go_mod()
                    tmp.run(["mod", "tidy"], True)

                if is_tidy or len(local_packages) > 0:
                    dry_run = tmp.run(["list", "-m", "all"], True)
                    packages.update(set(filter(None, map(line_to_package, dry_run.stdout.split('\n')))))

                return list(packages)

        except subprocess.CalledProcessError:
            # An erroring command does not install anything
            _log.info("The Go command encountered an error while collecting installation targets")
            return []

    def list_installed_packages(self) -> list[Package]:
        """
        List all installed `go` packages.

        Returns:
            A `list[Package]` representing all currently installed `go` packages.

        Raises:
            UnsupportedVersionError: The underlying `go` executable is of an unsupported version.
            RuntimeError: Failed to list installed `go` packages.
        """
        def line_to_package(line: str) -> Optional[Package]:
            # All supported versions adhere to this format
            components = line.strip().split()
            if len(components) == 2:
                return Package(self.ecosystem(), components[0], components[1])
            return None

        self._check_version()

        try:
            go_list_cmd = [self._executable, "list", "-m", "all"]
            list_cmd = subprocess.run(go_list_cmd, check=True, text=True, capture_output=True)
            return list(filter(None, map(line_to_package, list_cmd.stdout.split('\n'))))

        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to list installed go packages")

    def _check_version(self):
        """
        Check whether the underlying `go` executable is of a supported version.

        Raises:
            UnsupportedVersionError: The underlying `go` executable is of an unsupported version.
        """
        def get_go_version(executable: str) -> Optional[Version]:
            try:
                # All supported versions adhere to this format
                go_version = subprocess.run([executable, "version"], check=True, text=True, capture_output=True)
                match = re.search(r".*go(\d*(?:\.\d+)*).*", go_version.stdout.strip())
                return version_parse(match.group(1)) if match else None
            except InvalidVersion:
                return None

        go_version = get_go_version(self._executable)
        if not go_version or go_version < MIN_GO_VERSION:
            raise UnsupportedVersionError(f"Go before v{MIN_GO_VERSION} is not supported")

    def _normalize_command(self, command: list[str]) -> list[str]:
        """
        Normalize a `go` command.

        Args:
            command: A `list[str]` containing a `go` command line.

        Returns:
            The equivalent but normalized form of `command` with the initial `go`
            token replaced with the local filesystem path to `self.executable()`.

        Raises:
            ValueError: The given `command` is empty or not a valid `go` command.
        """
        if not command:
            raise ValueError("Received empty go command line")
        if command[0] != self.name():
            raise ValueError("Received invalid go command line")

        return [self._executable] + command[1:]
