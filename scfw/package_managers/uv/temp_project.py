"""
Provides helpers for resolving uv project dependencies via requirements export,
along with classes for spinning up ephemeral uv projects.
"""

import logging
import shutil
import subprocess
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Optional

try:
    import tomllib  # type: ignore[import-not-found]
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]

from typing_extensions import Self

from scfw.ecosystem import ECOSYSTEM
from scfw.package import LocalPackageSource, Package, RemotePackageSource
from scfw.package_managers.uv.common import (
    ALLOW_EXPORT_PREFIXES,
    PYTHON_VERSION_FILE,
    PYPROJECT_TOML,
    UV_ADD_VALUE_OPTIONS,
    UV_LOCK,
)

_log = logging.getLogger(__name__)


class TemporaryUvProject:
    """
    Prepares a temporary copy of an existing uv project.

    This class is used for commands such as `uv sync`, where the dependency
    resolution must reflect the existing project's pyproject.toml and uv.lock.
    """

    def __init__(self, executable: str):
        """
        Initialize a new TemporaryUvProject.

        Args:
            executable:
                The path to the uv executable.
        """
        self._temp_dir: Optional[TemporaryDirectory] = None
        self._executable = executable
        self.project_root = self._get_project_root(executable)

    def _get_project_root(
        self,
        executable: str,
    ) -> Optional[Path]:
        """
        Resolve the root directory of the current uv project.

        Args:
            executable:
                The path to the uv executable.

        Returns:
            The resolved project root path if valid, otherwise None.
        """
        try:
            command = [
                executable,
                "workspace",
                "dir",
            ]

            result = subprocess.run(
                command,
                check=True,
                text=True,
                capture_output=True,
                cwd=Path.cwd(),
            )
        except (
            subprocess.CalledProcessError,
            FileNotFoundError,
        ):
            return None

        uv_project = result.stdout.strip()

        if not uv_project:
            return None

        project_root = Path(uv_project)

        if (project_root / PYPROJECT_TOML).is_file():
            return project_root

        return None

    def __enter__(self) -> Self:
        """
        Create the temporary project directory.
        """
        if not self.project_root:
            raise RuntimeError(
                "Could not resolve uv project root. Ensure you are running inside a valid uv project."
            )

        self._temp_dir = TemporaryDirectory()
        temp_dir_path = Path(self._temp_dir.name)

        try:
            self._copy_project_files(
                self.project_root,
                temp_dir_path,
            )
        except Exception:
            self._temp_dir.cleanup()
            self._temp_dir = None
            raise

        return self

    def _copy_project_files(
        self,
        project_root: Path,
        temp_dir_path: Path,
    ) -> None:
        """
        Copy the uv project files required for dependency resolution,
        including workspace metadata for multi-package projects.

        Args:
            project_root:
                The root path of the source uv project.
            temp_dir_path:
                The target temporary directory path.

        Raises:
            RuntimeError:
                If the required pyproject.toml is missing from the project root.
        """
        orig_pyproject = project_root / PYPROJECT_TOML

        if not orig_pyproject.is_file():
            raise RuntimeError(
                f"Missing required project file: {orig_pyproject}"
            )

        shutil.copy2(
            orig_pyproject,
            temp_dir_path / PYPROJECT_TOML,
        )

        for filename in (
            UV_LOCK,
            PYTHON_VERSION_FILE,
        ):
            orig_file = project_root / filename

            if orig_file.is_file():
                shutil.copy2(
                    orig_file,
                    temp_dir_path / filename,
                )

        self._copy_workspace_metadata(project_root, temp_dir_path)

    def _copy_workspace_metadata(self, project_root: Path, temp_dir_path: Path) -> None:
        """
        Replicate workspace member pyproject.toml files so `uv export` can resolve
        the complete dependency graph without needing full source directory trees.

        Args:
            project_root:
                The root path of the source uv project.
            temp_dir_path:
                The target temporary directory path.
        """
        pyproject_path = project_root / PYPROJECT_TOML
        try:
            with pyproject_path.open("rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            _log.debug("Could not parse root pyproject.toml for workspace info: %s", e)
            return

        members = data.get("tool", {}).get("uv", {}).get("workspace", {}).get("members", [])

        for pattern in members:
            for member_dir in project_root.glob(pattern):
                member_pyproject = member_dir / PYPROJECT_TOML
                if member_pyproject.is_file():
                    rel_dir = member_dir.relative_to(project_root)
                    target_dir = temp_dir_path / rel_dir
                    target_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(member_pyproject, target_dir / PYPROJECT_TOML)

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """
        Release the temporary project resources.

        Args:
            exc_type:
                The exception class if an exception occurred within the context.
            exc_val:
                The exception instance if an exception occurred.
            exc_tb:
                The traceback object if an exception occurred.
        """
        if self._temp_dir is None:
            _log.warning(
                "No handle to temporary uv project directory found "
                "on context exit"
            )
            return

        self._temp_dir.cleanup()
        self._temp_dir = None

    def _temp_path(self) -> Path:
        """
        Return the path to the temporary project directory.

        Raises:
            RuntimeError:
                If called outside the context manager.
        """
        if not self._temp_dir:
            raise RuntimeError(
                "Cannot run commands in a temporary project environment "
                "outside of a context manager."
            )

        return Path(self._temp_dir.name)

    def _run_uv(
        self,
        command: list[str],
        cwd: Optional[Path] = None,
    ) -> subprocess.CompletedProcess[str]:
        """
        Run a uv command.

        Args:
            command:
                A normalized uv command beginning with the uv executable.

        cwd:
            Optional working directory. Defaults to the temporary project.

        Returns:
            The completed subprocess result.
        """
        working_directory = cwd or self._temp_path()

        _log.debug(
            "Running uv command in temp project: %s",
            " ".join(command),
        )

        return subprocess.run(
            command,
            check=True,
            text=True,
            capture_output=True,
            cwd=working_directory,
        )

    def resolve_sync_targets(self, command: list[str]) -> set[Package]:
        """
        Resolve the packages that `uv sync` would synchronize.

        The existing project is copied into a temporary directory and its
        resolved dependency set is exported directly by uv.

        Args:
            command:
                A normalized `uv sync` command.

        Returns:
            A set of resolved PyPI packages.
        """
        temp_dir_path = self._temp_path()
        requirements_file = temp_dir_path / f".scfw-reqs-{uuid.uuid4().hex[:8]}.txt"

        export_flags = [
            arg for arg in command[1:]
            if any(arg.startswith(prefix) for prefix in ALLOW_EXPORT_PREFIXES)
        ]

        export_command = [
            self._executable,
            "export",
            "--format",
            "requirements.txt",
            "--no-hashes",
            "--no-emit-workspace",
            *export_flags,
            "-o",
            str(requirements_file),
            "--project",
            str(temp_dir_path),
        ]

        try:
            self._run_uv(export_command)
            if not requirements_file.is_file():
                return set()
            return self._parse_requirements_file(requirements_file)
        except subprocess.CalledProcessError as e:
            _log.debug("Export failed during sync target resolution: %s", e.stderr)
            return set()
        finally:
            requirements_file.unlink(missing_ok=True)

    def resolve_add_targets(self, command: list[str]) -> set[Package]:
        """
        Resolve the explicitly requested packages and their transitive
        dependencies for `uv add` using the target project's context.

        Args:
            command:
                A normalized `uv add` command containing package targets and flags.

        Returns:
            A set of resolved PyPI packages.
        """
        targets = self._extract_add_targets(command)
        if not targets:
            return set()

        temp_dir_path = self._temp_path()
        lock_file = temp_dir_path / UV_LOCK
        packages_before: set[Package] = set()
        if lock_file.is_file():
            packages_before = self._parse_uv_lock(lock_file)

        try:
            add_command = [
                self._executable,
                "add",
                "--no-sync",
                *targets,
            ]

            self._run_uv(add_command, cwd=temp_dir_path)
            packages_after = self._parse_uv_lock(lock_file)
            before_map = {pkg.name: pkg.version for pkg in packages_before}

            return {
                pkg for pkg in packages_after
                if pkg.name not in before_map or before_map[pkg.name] != pkg.version
            }
        except subprocess.CalledProcessError as e:
            _log.debug("Package resolution failed during `uv add`: %s", e.stderr)
            return set()

    @staticmethod
    def _parse_uv_lock(lock_file: Path) -> set[Package]:
        """
        Parse a uv.lock file to extract resolved Package objects.

        Args:
            lock_file: Path to the generated uv.lock file.

        Returns:
            A set of resolved PyPI packages parsed from the lockfile data.
        """
        packages: set[Package] = set()
        if not lock_file.is_file():
            return packages

        data = tomllib.loads(lock_file.read_text(encoding="utf-8"))
        for pkg_data in data.get("package", []):
            name = pkg_data.get("name")
            version = pkg_data.get("version")
            pkg_source = pkg_data.get("source", {})

            if not name or not version:
                continue

            if isinstance(pkg_source, dict) and "virtual" in pkg_source:
                continue

            resolved_source: LocalPackageSource | RemotePackageSource | None = None
            if wheels := pkg_data.get("wheels"):
                if url := wheels[0].get("url"):
                    resolved_source = RemotePackageSource(url)
            elif sdist := pkg_data.get("sdist"):
                if url := sdist.get("url"):
                    resolved_source = RemotePackageSource(url)

            # Fallback to registry URL
            if resolved_source is None:
                if isinstance(pkg_source, dict) and (registry_url := pkg_source.get("registry")):
                    resolved_source = RemotePackageSource(registry_url)
                else:
                    resolved_source = RemotePackageSource("https://pypi.org/simple")

            packages.add(
                Package(
                    ecosystem=ECOSYSTEM.PyPI,
                    name=name,
                    version=version,
                    source=resolved_source,
                )
            )

        return packages

    def _parse_requirements_file(self, requirements_file: Path) -> set[Package]:
        """
        Parse a requirements.txt generated by uv export into Package targets.

        Args:
            requirements_file:
                Path to the generated requirements.txt file.

        Returns:
            A set of parsed SCFW Package targets.
        """
        packages: set[Package] = set()
        default_source = RemotePackageSource("https://pypi.org/simple")

        for line in requirements_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Get package name and version
            if "==" in line:
                name, version = line.split("==", 1)
                name = name.split("[")[0].strip()
                version = version.split(";")[0].strip()

                packages.add(
                    Package(
                        ecosystem=ECOSYSTEM.PyPI,
                        name=name,
                        version=version,
                        source=default_source,
                    )
                )

        return packages

    def _extract_add_targets(self, command: list[str]) -> list[str]:
        """
        Extract explicit package targets from a `uv add` command.

        Args:
            command:
                The argument list representing a `uv add` command.

        Returns:
            A list of positional target arguments representing requested packages.
        """
        if "add" not in command:
            return []

        args = iter(command[command.index("add") + 1:])
        targets: list[str] = []

        for arg in args:
            if arg == "--":
                targets.extend(args)
                break

            if arg.startswith("-"):
                if "=" in arg:
                    continue

                if arg in UV_ADD_VALUE_OPTIONS:
                    next(args, None)

                continue

            targets.append(arg)

        return targets
