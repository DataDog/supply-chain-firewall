"""
Provides a class for spinning up ephemeral npm projects to run commands in.
"""

import json
import logging
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Any, Optional, Type
from typing_extensions import Self

_log = logging.getLogger(__name__)


class TemporaryNpmProject:
    """
    Prepares a temporary npm project that duplicates a given one, allowing for executing
    `npm` commands in the context of that project safely and without affecting the original.

    This class implements the context manager protocol, and indeed, the temporary resources
    needed by this class to run commands exist exist only while inside a context. Invoking
    this class' methods outside of a context will result in error.
    """
    def __init__(self, project_root: Path):
        """
        Initialize a new `TemporaryNpmProject`.

        Args:
            project_root:
                A `Path` in the local filesystem to the project root of the reference
                npm project that should be duplicated into the temporary one.
        """
        self._tmp_dir: Optional[TemporaryDirectory] = None

        self._package_json: Optional[Path] = None

        self.project_root = project_root

    def __enter__(self) -> Self:
        """
        Convert a `TemporaryNpmProject` into a context manager.

        Returns:
            The given `TemporaryNpmProject` instance, now as a context manager.
        """
        self._tmp_dir = TemporaryDirectory()
        tmp_dir_path = Path(self._tmp_dir.name)

        orig_package_json = self.project_root / "package.json"
        if not orig_package_json.is_file():
            raise RuntimeError(f"Project root directory {self.project_root} does not contain a package.json file")

        temp_package_json = tmp_dir_path / "package.json"
        shutil.copy(orig_package_json, temp_package_json)
        self._package_json = temp_package_json

        orig_package_lock = self.project_root / "package-lock.json"
        if orig_package_lock.is_file():
            shutil.copy(orig_package_lock, tmp_dir_path / "package-lock.json")
        else:
            _log.info(f"Project root directory {self.project_root} does not contain a package-lock.json file")

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
        self._package_json = None

        if self._tmp_dir is None:
            _log.warning("No handle to temporary npm project directory found on context exit")
            return

        self._tmp_dir.cleanup()
        self._tmp_dir = None

    def install_to_lockfile(self, install_command: list[str]) -> Optional[dict[str, Any]]:
        """
        Safely run an `npm install` command in a temporary environment and return the
        updated `package-lock.json` file.

        Args:
            install_command:
                The `npm install` command to run in the temporary environment. It is the
                caller's responsibility to ensure that only install commands are passed
                to this function.

        Returns:
            A `dict[str, Any]` containing the contents of the updated `package-lock.json`
            file after safely running the given `npm install` command, or `None` if no
            `package-lock.json` file was written by the command.

        Raises:
            RuntimeError:
                The method was invoked outside of a context or failed to resolve npm
                installation targets
        """
        if not (self._tmp_dir and self._package_json):
            raise RuntimeError("Cannot run commands in a temporary npm environment outside of a context")

        try:
            tmp_dir_path = Path(self._tmp_dir.name)

            # Safely run the given `npm install` command to write or update the lockfile
            # All supported versions of npm support these additional `install` command options
            install_command = install_command + ["--package-lock-only", "--ignore-scripts"]
            subprocess.run(install_command, check=True, text=True, capture_output=True, cwd=tmp_dir_path)

            package_lock_path = tmp_dir_path / "package-lock.json"
            if not package_lock_path.is_file():
                return None

            with open(package_lock_path) as f:
                return json.load(f)

        except Exception as e:
            raise RuntimeError(f"Failed to resolve npm installation targets: {e}")
