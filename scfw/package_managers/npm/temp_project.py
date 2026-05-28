"""
Provides a class for spinning up ephemeral npm projects to run commands in.
"""

import functools
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Any, Optional, Type
from typing_extensions import Self

from scfw.ecosystem import ECOSYSTEM
from scfw.package import LocalPackageSource, Package, RemotePackageSource

_log = logging.getLogger(__name__)

# URI scheme for npm local package dependencies
_LOCAL_DEPENDENCY_PREFIX = "file:"


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
        def get_project_root(executable: str) -> Optional[Path]:
            npm_prefix_command = [executable, "prefix"]
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
            self.project_root = get_project_root(executable)
        except Exception as e:
            raise RuntimeError(f"Failed to resolve npm project root: {e}")

    def __enter__(self) -> Self:
        """
        Convert a `TemporaryNpmProject` into a context manager.

        Returns:
            The given `TemporaryNpmProject` instance, now as a context manager.
        """
        def rewrite_relative_path(relative_path: str, project_root: Path, temp_dir_path: Path) -> str:
            absolute_path = (project_root / relative_path).resolve()
            return os.path.relpath(absolute_path, temp_dir_path.resolve())

        def copy_package_json(project_root: Path, temp_dir_path: Path):
            orig_package_json = project_root / "package.json"
            if not orig_package_json.is_file():
                return

            with open(orig_package_json) as f:
                temp_content = json.load(f)

            # Re-relativize local dependency paths to the temporary project directory
            for section in {"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}:
                dependencies = temp_content.get(section)
                if not isinstance(dependencies, dict):
                    continue

                for name, spec in dependencies.items():
                    if isinstance(spec, str) and spec.startswith(_LOCAL_DEPENDENCY_PREFIX):
                        relative_target = rewrite_relative_path(
                            spec[len(_LOCAL_DEPENDENCY_PREFIX):],
                            project_root,
                            temp_dir_path,
                        )
                        dependencies[name] = f"{_LOCAL_DEPENDENCY_PREFIX}{relative_target}"

            with open(temp_dir_path / "package.json", 'w') as f:
                json.dump(temp_content, f)

        def copy_lockfile(project_root: Path, temp_dir_path: Path):
            temp_lockfile = temp_dir_path / "package-lock.json"

            orig_lockfile = project_root / "package-lock.json"
            if not orig_lockfile.is_file():
                return

            with open(orig_lockfile) as f:
                temp_content = json.load(f)

            packages = temp_content.get("packages")
            if not isinstance(packages, dict):
                shutil.copy(orig_lockfile, temp_lockfile)
                return

            # External entry keys (anything other than "" or a `node_modules/...` path)
            # are paths to linked sources, relative to the original project root
            for old_key in list(packages.keys()):
                if old_key == "" or old_key.startswith("node_modules/"):
                    continue
                packages[rewrite_relative_path(old_key, project_root, temp_dir_path)] = packages.pop(old_key)

            # `resolved` fields on link entries are relative paths from the project root,
            # usually bare (`./` or `../` prefixed) but occasionally `file:`-prefixed.
            # `dependencies.<name>` values may carry `file:` specs in the same form.
            for entry in packages.values():
                if not isinstance(entry, dict):
                    continue

                resolved = entry.get("resolved")
                if isinstance(resolved, str):
                    if resolved.startswith(_LOCAL_DEPENDENCY_PREFIX):
                        resolved = rewrite_relative_path(
                            resolved[len(_LOCAL_DEPENDENCY_PREFIX):],
                            project_root,
                            temp_dir_path,
                        )
                        entry["resolved"] = f"{_LOCAL_DEPENDENCY_PREFIX}{resolved}"
                    elif resolved.startswith(("./", "../")):
                        entry["resolved"] = rewrite_relative_path(resolved, project_root, temp_dir_path)

                dependencies = entry.get("dependencies")
                if isinstance(dependencies, dict):
                    for name, spec in dependencies.items():
                        if isinstance(spec, str) and spec.startswith(_LOCAL_DEPENDENCY_PREFIX):
                            spec = rewrite_relative_path(
                                spec[len(_LOCAL_DEPENDENCY_PREFIX):],
                                project_root,
                                temp_dir_path,
                            )
                            dependencies[name] = f"{_LOCAL_DEPENDENCY_PREFIX}{spec}"

            with open(temp_lockfile, 'w') as f:
                json.dump(temp_content, f)

        def copy_node_modules(project_root: Path, temp_dir_path: Path):
            orig_node_modules = project_root / "node_modules"
            if not orig_node_modules.is_dir():
                return

            temp_node_modules = temp_dir_path / "node_modules"
            shutil.copytree(orig_node_modules, temp_node_modules, symlinks=True)

            # Re-relativize relative symlinks to the temporary project directory
            for root, dirs, files in os.walk(temp_node_modules, followlinks=False):
                for name in dirs + files:
                    entry = Path(root) / name
                    if not entry.is_symlink():
                        continue

                    target = os.readlink(entry)
                    if os.path.isabs(target):
                        continue

                    orig_entry = orig_node_modules / entry.relative_to(temp_node_modules)
                    absolute_target = (orig_entry.parent / target).resolve()
                    entry.unlink()
                    os.symlink(absolute_target, entry)

        def copy_from_project_root(project_root: Path, temp_dir_path: Path, file: str):
            orig_file = project_root / file
            if not orig_file.is_file():
                return

            shutil.copy(orig_file, temp_dir_path / file)

        self._temp_dir = TemporaryDirectory()
        if not self.project_root:
            return self

        temp_dir_path = Path(self._temp_dir.name)

        copy_package_json(self.project_root, temp_dir_path)
        copy_lockfile(self.project_root, temp_dir_path)
        copy_node_modules(self.project_root, temp_dir_path)

        # Copy any other relevant files that may be present in the project root
        for file in {".npmrc"}:
            copy_from_project_root(self.project_root, temp_dir_path, file)

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
            ValueError: The given `install_command` is empty or not a valid `npm` command.
        """
        def extract_target_handles(dry_run_log: list[str]) -> list[str]:
            target_handles = []

            # All supported npm versions adhere to this format
            for line in dry_run_log:
                line_tokens = line.split()

                if line_tokens[1] in {"sill", "silly"} and line_tokens[2] in {"ADD", "CHANGE"}:
                    target_handles.append(line_tokens[3])

            return target_handles

        def handle_to_install_target(
            dependencies: dict[str, Any],
            target_handle: str,
            target_name: Optional[str] = None,
            target_source: Optional[LocalPackageSource | RemotePackageSource] = None,
        ) -> Package:
            if not target_name:
                # All supported npm versions adhere to this format
                target_name = target_handle.rpartition("node_modules/")[2]

            if not (target_entry := dependencies.get(target_handle)):
                raise KeyError(
                    f"Missing entry for installation target {target_name} in package-lock.json"
                )
            if not (version := target_entry.get("version")):
                # Parse recursively if this entry links to another
                # All supported npm versions adhere to this format
                if target_entry.get("link") and (resolved_handle := target_entry.get("resolved")):
                    # Some versions of npm prefix the link target with `file:`; the linked
                    # entry's key is the bare path, so normalize before lookup
                    if resolved_handle.startswith(_LOCAL_DEPENDENCY_PREFIX):
                        resolved_handle = resolved_handle[len(_LOCAL_DEPENDENCY_PREFIX):]
                    # `copy_lockfile` rewrites link keys so that `temp_dir_path / resolved_handle`
                    # resolves back to the original local package on the user's filesystem
                    link_source = LocalPackageSource((temp_dir_path / resolved_handle).resolve())
                    return handle_to_install_target(dependencies, resolved_handle, target_name, link_source)

                raise KeyError(
                    f"Missing version data for installation target {target_name} in package-lock.json"
                )

            # Derive source from this entry's `resolved` field unless a caller already supplied one
            if target_source is None and (resolved := target_entry.get("resolved")):
                if resolved.startswith("http"):
                    target_source = RemotePackageSource(resolved)
                elif resolved.startswith(_LOCAL_DEPENDENCY_PREFIX):
                    target_source = LocalPackageSource(
                        (temp_dir_path / resolved[len(_LOCAL_DEPENDENCY_PREFIX):]).resolve()
                    )

            return Package(ECOSYSTEM.Npm, target_name, version, source=target_source)

        if not self._temp_dir:
            raise RuntimeError("Cannot run commands in a temporary npm environment outside of a context")

        temp_dir_path = Path(self._temp_dir.name)

        # Validate and normalize `command` with respect to the given npm executable
        # Coerce global commands into local ones so they resolve into the temp project
        install_command = self._normalize_command(install_command)
        install_command = [token for token in install_command if token not in {"-g", "--global"}]

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
            if not (dependencies := json.load(f).get("packages")):
                raise KeyError("Missing dependencies data in package-lock.json")

        # Read added and changed packages out of the lockfile
        install_targets: set[Package] = functools.reduce(
            lambda acc, target_handle: acc | {handle_to_install_target(dependencies, target_handle)},
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
