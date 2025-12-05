"""
Provides a class for spinning up ephemeral npm projects to run commands in.
"""

import logging
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Optional, Type
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
        self._tmp_dir_path: Optional[Path] = None

        self._package_json: Optional[Path] = None
        self._package_lock: Optional[Path] = None

        self.project_root = project_root

    def __enter__(self) -> Self:
        """
        Convert a `TemporaryNpmProject` into a context manager.

        Returns:
            The given `TemporaryNpmProject` instance, now as a context manager.
        """
        self._tmp_dir = TemporaryDirectory()
        self._tmp_dir_path = Path(self._tmp_dir.name)

        orig_package_json = self.project_root / "package.json"
        if not orig_package_json.is_file():
            raise RuntimeError(f"Project root directory {self.project_root} does not contain a package.json file")

        temp_package_json = self._tmp_dir_path / "package.json"
        shutil.copy(orig_package_json, temp_package_json)
        self._package_json = temp_package_json

        self._package_lock = None
        orig_package_lock = self.project_root / "package-lock.json"

        if orig_package_lock.is_file():
            temp_package_lock = self._tmp_dir_path / "package-lock.json"
            shutil.copy(orig_package_lock, temp_package_lock)
            self._package_lock = temp_package_lock
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
        self._package_lock = None
        self._package_json = None
        self._tmp_dir_path = None

        if self._tmp_dir is None:
            _log.warning("No handle to temporary npm project directory found on context exit")
            return

        self._tmp_dir.cleanup()
        self._tmp_dir = None
