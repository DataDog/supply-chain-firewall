"""
Providers helpers for resolving uv project dependencies via requirements export,
along with a class for spinning up an ephemeral copy of a uv project to run them in.
"""

import logging
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Optional
from typing_extensions import Self

from scfw.package import Package
from scfw.package_managers.uv.common import UV_LOCK, PYPROJECT_TOML, PYTHON_VERSION_FILE

_log = logging.getLogger(__name__)


class TemporaryUvProject:
    """
    Prepares a temporary uv project that duplicates a given one, allowing for executing
    `uv` commands in the context of that project safely and withoiut affecting the original.

    This class implements the context manager protocol, and indeed, the temporary resources
    needed by this class to run commands that exist only while inside a context. Invoking this
    class' methods outside of a context will result in an error.
    """
    def __init__(self, executable: str):
        """
        Initialize a new `TemporaryUvProject`.

        Args:
            executable: the path to the `uv` executable
        """
        self._temp_dir: Optional[TemporaryDirectory] = None
        self._executable = executable

        try:
            self.project_root = self._get_project_root(executable)
        except Exception as e:
            raise RuntimeError(f"Failed to resolve uv project root: {e}")

    def _get_project_root(self, executable: str) -> Optional[Path]:
        """
        Resolves the root directory of the current uv project.
        """
        try:
            uv_project_root_command: list[str] = [executable, "workspace", "dir"]
            uv_project_root_process = subprocess.run(
                uv_project_root_command,
                check=True,
                text=True,
                capture_output=True,
                cwd=Path.cwd(),
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

        uv_project = uv_project_root_process.stdout.strip()
        if not uv_project:
            return None

        project_root = Path(uv_project)
        if (project_root / PYPROJECT_TOML).is_file():
            return project_root

        return None

    def __enter__(self) -> Self:
        """
        Convert a `TemporaryUvProject` instance into a context manager.

        Returns:
            The given `TemporaryUvProject` instance, now as a context manager.
        """
        if not self.project_root:
            raise RuntimeError("Could not resolve uv project root")

        self._temp_dir = TemporaryDirectory()
        temp_dir_path = Path(self._temp_dir.name)

        try:
            self._copy_project_files(self.project_root, temp_dir_path)
        except Exception:
            self._temp_dir.cleanup()
            self._temp_dir = None
            raise

        return self

    def _copy_project_files(self, project_root: Path, temp_dir_path: Path) -> None:
        """
        Copies uv.lock, pyproject.toml, and other optional files to the temporary project directory.
        """
        orig_pyproject = project_root / PYPROJECT_TOML
        if not orig_pyproject.is_file():
            raise RuntimeError(f"Missing required project file: {orig_pyproject}")

        shutil.copy2(orig_pyproject, temp_dir_path / PYPROJECT_TOML)

        for filename in (UV_LOCK, PYTHON_VERSION_FILE):
            orig_file = project_root / filename
            if orig_file.is_file():
                shutil.copy2(orig_file, temp_dir_path / filename)

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """
        Release the underlying `TemporaryUvProject` resources on context manager exit.
        """
        if self._temp_dir is None:
            _log.warning("No handle to temporary uv project directory found on context exit")
            return

        self._temp_dir.cleanup()
        self._temp_dir = None

    def resolve_via_export(self) -> set[Package]:
        """
        Export the requirements of a uv project referenced by `uv export` as
        a requirements.txt file inside the temporary environment.
        """
        if not self._temp_dir:
            raise RuntimeError("Cannot run commands in a temporary project environment outside of a context manager")

        from scfw.package_managers.pip import Pip

        temp_dir_path = Path(self._temp_dir.name)
        requirements_file = temp_dir_path / "requirements.txt"

        export_command = [
            self._executable,
            "export",
            "--format",
            "requirements.txt",
            "--no-hashes",
            "--no-emit-project",
            "-o",
            str(requirements_file),
            "--project",
            str(temp_dir_path),
        ]

        try:
            subprocess.run(export_command, check=True, text=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            _log.error("Failed to export uv project requirements: %s", e)
            raise

        if not requirements_file.is_file():
            return set()

        pip = Pip()
        return pip.resolve_install_targets(["pip", "install", "-r", str(requirements_file)])
