"""
Provides a class for spinning up ephemeral npm projects to run commands in.
"""

import functools
import json
import logging
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Any, Optional, Type
from typing_extensions import Self

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package

_log = logging.getLogger(__name__)


class TemporaryNpmProject:
    """
    Prepares a temporary npm project that duplicates a given one, allowing for executing
    `npm` commands in the context of that project safely and without affecting the original.

    This class implements the context manager protocol, and indeed, the temporary resources
    needed by this class to run commands exist exist only while inside a context. Invoking
    this class' methods outside of a context will result in error.
    """
    def __init__(self, executable: str):
        """
        Initialize a new `TemporaryNpmProject`.
        """
        def get_project_root() -> Optional[Path]:
            npm_prefix_command = self._normalize_command(["npm", "prefix"])
            npm_prefix_process = subprocess.run(npm_prefix_command, check=True, text=True, capture_output=True)

            npm_prefix = npm_prefix_process.stdout.strip()
            if not npm_prefix:
                raise RuntimeError("Project root resolution returned no output")

            project_root = Path(npm_prefix)
            package_json_path = project_root / "package.json"

            return project_root if package_json_path.is_file() else None

        self._temp_dir: Optional[TemporaryDirectory] = None
        self._executable = executable

        try:
            self.project_root = get_project_root()
        except Exception as e:
            raise RuntimeError(f"Failed to resolve npm project root: {e}")

    def __enter__(self) -> Self:
        """
        Convert a `TemporaryNpmProject` into a context manager.

        Returns:
            The given `TemporaryNpmProject` instance, now as a context manager.
        """
        def copy_from_project_root(temp_dir_path: Path, resource: str, is_dir: bool = False):
            if not self.project_root:
                return

            orig_resource = self.project_root / resource
            temp_resource = temp_dir_path / resource

            if is_dir and orig_resource.is_dir():
                shutil.copytree(orig_resource, temp_resource)
            elif not is_dir and orig_resource.is_file():
                shutil.copy(orig_resource, temp_resource)
            else:
                resource_kind = "directory" if is_dir else "file"
                _log.info(
                    f"Project root directory {self.project_root} does not contain a {resource} {resource_kind}"
                )

        self._temp_dir = TemporaryDirectory()
        temp_dir_path = Path(self._temp_dir.name)

        copy_from_project_root(temp_dir_path, "package.json")
        copy_from_project_root(temp_dir_path, "package-lock.json")
        copy_from_project_root(temp_dir_path, "node_modules", is_dir=True)

        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ):
        """
        Release the underlying `TemporaryNpmProject` resources on context manager exit.
        """
        if self._temp_dir is None:
            _log.warning("No handle to temporary npm project directory found on context exit")
            return

        self._temp_dir.cleanup()
        self._temp_dir = None

    def resolve_install_command_targets(self, install_command: list[str]) -> list[Package]:
        """
        Resolve installation targets for an `npm install` command in the temporary environment.

        Args:
            install_command:
                The `npm install` command whose installation targets should be resolved
                in the context of the temporary environment. It is the caller's responsibility
                to ensure only `npm install` commands are passed to this method.

        Returns:
            A `list[Package]` representing the set of installation targets that would be
            installed by the given `npm install` command.

        Raises:
            RuntimeError:
              * This method was invoked outside of a context (i.e., with no backing resources)
              * Required `package-lock.json` file was not written while resolving installation targets
            KeyError: The `package-lock.json` file is malformed or missing data for installation targets
            ValueError: Failed to parse installation target specification (malformed verbose log output)
        """
        def is_global_command(command: list[str]) -> bool:
            return any(global_opt in command for global_opt in {"-g", "--global"})

        def extract_placed_dependencies(dry_run_log: list[str]) -> list[Package]:
            placed_dependencies = []

            # All supported npm versions adhere to this format
            for line in dry_run_log:
                line_tokens = line.split()

                if line_tokens[2] != "placeDep":
                    continue
                target_spec = line_tokens[4]

                name, sep, version = target_spec.rpartition('@')
                if not (name and sep):
                    raise ValueError(f"Failed to parse npm installation target specification '{target_spec}'")

                placed_dependencies.append(Package(ECOSYSTEM.Npm, name, version))

            return placed_dependencies

        def extract_target_handles(dry_run_log: list[str]) -> list[str]:
            target_handles = []

            # All supported npm versions adhere to this format
            for line in dry_run_log:
                line_tokens = line.split()

                if line_tokens[1] in {"sill", "silly"} and line_tokens[2] in {"ADD", "CHANGE"}:
                    target_handles.append(line_tokens[3])

            return target_handles

        def handle_to_package(lockfile: dict[str, Any], target_handle: str) -> Package:
            # All supported npm versions adhere to this format
            target_name = target_handle.rpartition("node_modules/")[2]

            if not (dependencies := lockfile.get("packages")):
                raise KeyError("Missing dependencies data in package-lock.json")
            if not (target_entry := dependencies.get(target_handle)):
                raise KeyError(
                    f"Missing entry for installation target {target_name} in package-lock.json"
                )
            if not (version := target_entry.get("version")):
                raise KeyError(
                    f"Missing version data for installation target {target_name} in package-lock.json"
                )

            return Package(ECOSYSTEM.Npm, name=target_name, version=version)

        if not self._temp_dir:
            raise RuntimeError("Cannot run commands in a temporary npm environment outside of a context")

        temp_dir_path = Path(self._temp_dir.name)

        # Validate and normalize `command` with respect to the given npm executable
        install_command = self._normalize_command(install_command)

        # First, perform a dry-run of the installation and collect the verbose log output
        try:
            dry_run_command = install_command + ["--dry-run", "--loglevel", "silly"]
            dry_run_process = subprocess.run(
                dry_run_command,
                check=True,
                text=True,
                capture_output=True,
                cwd=temp_dir_path,
            )
        except subprocess.CalledProcessError:
            _log.info("Input npm install command results in error: nothing will be installed")
            return []

        dry_run_log = dry_run_process.stderr.strip().split('\n')

        # We need only look at placed dependencies for commands run outside of a project scope
        if not self.project_root or is_global_command(install_command):
            return extract_placed_dependencies(dry_run_log)

        # Each target handle corresponds to a (possibly duplicated) installation target
        target_handles = extract_target_handles(dry_run_log)
        if not target_handles:
            return []

        # Safely run the given `npm install` command to write or update the lockfile
        # All supported versions of npm support these additional `install` command options
        install_command = install_command + ["--package-lock-only", "--ignore-scripts"]
        subprocess.run(install_command, check=True, text=True, capture_output=True, cwd=temp_dir_path)

        # Parse the updated lockfile JSON
        lockfile_path = temp_dir_path / "package-lock.json"
        if not lockfile_path.is_file():
            raise RuntimeError(
                "Required package lockfile was not written while resolving installation targets"
            )
        with open(lockfile_path) as f:
            lockfile = json.load(f)

        # Read the target versions for added and changed packages out of the lockfile
        install_targets = functools.reduce(
            lambda acc, target_handle: acc | {handle_to_package(lockfile, target_handle)},
            target_handles,
            set(),
        )

        return list(install_targets)

    def _normalize_command(self, command: list[str]) -> list[str]:
        """
        Normalize an `npm` command.

        Args:
            command: A `list[str]` containing an `npm` command line.

        Returns:
            The equivalent but normalized form of `command` with the initial `"npm"`
            token replaced with the local filesystem path to an `npm` executable.

        Raises:
            ValueError: The given `command` is empty or not a valid `npm` command.
        """
        if not command:
            raise ValueError("Received empty npm command line")
        if command[0] != "npm":
            raise ValueError("Received invalid npm command line")

        return [self._executable] + command[1:]
