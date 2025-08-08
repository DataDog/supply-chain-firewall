"""
Defines a subclass of `PackageManagerCommand` for `go` commands.
"""

import logging
import os
import pathlib
import platform
import re
import shutil
import subprocess
import tempfile
from types import TracebackType
from typing import Optional, Type, TypeVar

from packaging.version import InvalidVersion, Version, parse as version_parse

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_manager import PackageManager, UnsupportedVersionError

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
            UnsupportedVersionError: The underlying `go` executable is of an unsupported version.
        """
        def get_go_version(executable: str) -> Version:
            try:
                # All supported versions adhere to this format
                go_version = subprocess.run([executable, "version"], check=True, text=True, capture_output=True)
                if (match := re.search(r".*go(\d*(?:\.\d+)*).*", go_version.stdout.strip())):
                    return version_parse(match.group(1))
                raise UnsupportedVersionError("Failed to parse Go version output")
            except InvalidVersion:
                raise UnsupportedVersionError("Failed to parse Go version number")

        executable = executable if executable else shutil.which(self.name())
        if not executable:
            raise RuntimeError("Failed to resolve local Go executable")
        if not os.path.isfile(executable):
            raise RuntimeError(f"Path '{executable}' does not correspond to a regular file")

        if get_go_version(executable) < MIN_GO_VERSION:
            raise UnsupportedVersionError(f"Go before v{MIN_GO_VERSION} is not supported")

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

    def run_command(self, command: list[str]):
        """
        Run a `go` command.

        Args:
            command: A `list[str]` containing a `go` command to execute.

        Raises:
            ValueError: The given `command` is empty or not a valid `go` command.
        """
        subprocess.run(self._normalize_command(command))

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
            GoModNotFoundError: No `go.mod` file was found for the given `go` command.
        """
        _TempGoEnvironmentType = TypeVar('_TempGoEnvironmentType', bound='TempGoEnvironment')

        class TempGoEnvironment(tempfile.TemporaryDirectory):
            """
            Prepares a temporary environment in which go commands may be executed
            without affecting the user's global environment.

            This may be used as a context manager. On completion of the context
            the temporary environment will be removed from the filesystem, alongside
            any changes that may have been made to the current project.

            Alternatively, when done with the environment, you may call cleanup()
            to remove the temporary environment.
            """
            def __init__(self, executable: str):
                """
                Initialize a new `TempGoEnvironment`.

                Args:
                    executable: Path to the `go` binary.
                """
                tempfile.TemporaryDirectory.__init__(self)

                self._executable = executable
                self._restore_mod_file = False
                self._restore_sum_file = False
                self._remove_sum_file = False
                self._original_dir = None

                gomod_command = [self._executable, "env", "GOMOD"]
                gomod = subprocess.run(gomod_command, check=True, text=True, capture_output=True)
                gomod_path = gomod.stdout.strip()
                if gomod_path != "/dev/null" and gomod_path != "NUL":
                    self._original_dir = pathlib.Path(gomod_path).absolute().parent

                self._create_tmp_env()

            def _create_tmp_env(self):
                """
                Create the temporary environment and set every environment variable
                required to run `go` commands keeping the global environment clean.
                """
                self.tmp_dir = pathlib.Path(self.name)

                go_dir = self.tmp_dir / "go"
                go_dir.mkdir(mode=0o750)

                self._dry_run_dir = self.tmp_dir / "dry_run"
                self._dry_run_dir.mkdir(mode=0o750)

                cache_dir = self.tmp_dir / "cache"
                cache_dir.mkdir(mode=0o750)

                mod_cache_dir = self.tmp_dir / "mod_cache"
                mod_cache_dir.mkdir(mode=0o750)

                # Go searches each directory listed in GOPATH to find source code,
                # but new packages are always downloaded into the first directory
                # in the list.
                gopath_command = [self._executable, "env", "GOPATH"]
                gopath = subprocess.run(gopath_command, check=True, text=True, capture_output=True)

                separator = ":"
                if platform.system() == "Windows":
                    separator = ";"

                self.env = os.environ.copy()
                self.env['GOPATH'] = f"{go_dir}{separator}{gopath.stdout.strip()}"
                self.env['GOCACHE'] = str(cache_dir)
                self.env['GOMODCACHE'] = str(mod_cache_dir)

            def __enter__(self: _TempGoEnvironmentType) -> _TempGoEnvironmentType:
                """
                Convert the `TempGoEnvironment` to a context manager.

                Returns:
                    The object itself managing the temporary environment.
                """
                return self

            def cleanup(self):
                """
                Clear the temporary environment and undo any changes made to the current project.
                """
                if self._original_dir is not None:
                    if self._restore_mod_file:
                        mod_file = self._original_dir / "go.mod"
                        tmp_file = self.tmp_dir / "go.mod"
                        shutil.copy(tmp_file, mod_file)

                    sum_file = self._original_dir / "go.sum"
                    if self._restore_sum_file:
                        tmp_file = self.tmp_dir / "go.sum"
                        shutil.copy(tmp_file, sum_file)
                    elif self._remove_sum_file:
                        os.remove(sum_file)

                tempfile.TemporaryDirectory.cleanup(self)

            def __exit__(
                self,
                exc_type: Optional[Type[BaseException]],
                exc_val: Optional[BaseException],
                exc_tb: Optional[TracebackType],
            ):
                """
                Clear the temporary environment and undo any changes made to the current project.
                """
                self.cleanup()

            def run(self, args: list[str], local: bool = False) -> subprocess.CompletedProcess:
                """
                Execute a go command within the temporary environment.

                Args:
                    args: The list of arguments passed to `go`.
                Returns:
                    A representation of the finished proccess.
                """
                cwd = self._dry_run_dir
                if local:
                    cwd = None

                command = [self._executable] + args
                return subprocess.run(command, cwd=cwd, env=self.env, check=True, text=True, capture_output=True)

            def duplicate_go_mod(self):
                """
                Duplicate the go.mod and go.sum in the nearest ancestor directory.

                On clean up, these files are recovered, in case they were modified.
                """
                if self._original_dir is None:
                    raise GoModNotFoundError("Failed to find a 'go.mod' file to operate on")

                mod_file = self._original_dir / "go.mod"
                shutil.copy(mod_file, self.tmp_dir)
                self._restore_mod_file = True

                sum_file = self._original_dir / "go.sum"
                if sum_file.exists():
                    shutil.copy(sum_file, self.tmp_dir)
                    self._restore_sum_file = True
                else:
                    self._remove_sum_file = True

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
                    is_local = pathlib.Path(param).exists()
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

    def list_installed_packages(self) -> list[Package]:
        """
        List all installed packages.

        Returns:
            A `list[Package]` representing all currently installed packages.
        """
        def line_to_package(line: str) -> Optional[Package]:
            # All supported versions adhere to this format
            components = line.strip().split()
            if len(components) == 2:
                return Package(self.ecosystem(), components[0], components[1])
            return None

        try:
            go_list_cmd = [self._executable, "list", "-m", "all"]
            list_cmd = subprocess.run(go_list_cmd, check=True, text=True, capture_output=True)
            return list(filter(None, map(line_to_package, list_cmd.stdout.split('\n'))))
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to list go installed packages")


class GoModNotFoundError(Exception):
    """
    An exception that occurs when an attempt is made to execute a go command that
    must be executed within a go project (with a go.mod file), but not such file
    could be found in the direct directory hierarchy.
    """
    pass
