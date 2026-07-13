"""
Provides a class for spinning up an ephemeral copy of a Poetry project, along with
helpers for resolving a `(name, version)` package source mapping from a Poetry
project's lock file.
"""

import logging
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Optional

try:
    import tomllib  # type: ignore[import-not-found]
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]

from scfw.package import LocalPackageSource, RemotePackageSource

_log = logging.getLogger(__name__)

_PYPI_PROJECT_BASE_URL = "https://pypi.org/project"


def get_source_map(
    executable: str, command: list[str]
) -> dict[tuple[str, str], LocalPackageSource | RemotePackageSource]:
    """
    Return a `(name, version)` source mapping for the project referenced by `command`.

    Locates the project directory via the `--directory`/`-C` flag in `command`,
    falling back to the current working directory. If a `poetry.lock` already
    exists there it is parsed directly; otherwise, one is generated from scratch
    in a temporary copy of the project, which is never itself modified.

    Returns an empty dict (and logs a warning) on any failure so callers can
    degrade gracefully to returning packages without source information.
    """
    project_dir = _resolve_project_dir(command)

    try:
        lock_path = project_dir / "poetry.lock"
        if lock_path.is_file():
            return _parse_lock_file(lock_path)

        with TemporaryPoetryProject(project_dir) as temp_dir:
            _log.warning("No poetry.lock found; generating one in a temporary directory (this may be slow)")

            result = subprocess.run([executable, "lock"], cwd=temp_dir, text=True, capture_output=True)
            if result.returncode != 0:
                _log.warning(
                    "Failed to generate poetry.lock in temporary directory (rc=%s): %s",
                    result.returncode,
                    (result.stderr or result.stdout).strip(),
                )

            lock_path = temp_dir / "poetry.lock"
            return _parse_lock_file(lock_path) if lock_path.is_file() else {}

    except Exception as e:
        _log.warning("Could not determine package sources from poetry.lock: %s", e, exc_info=True)
        return {}


def resolve_via_lock(
    command: list[str]
) -> dict[tuple[str, str], LocalPackageSource | RemotePackageSource]:
    """
    Run an `add`/`update` `command` with `--lock` against a temporary copy of its
    project, never touching the original project, and report the packages it
    introduces. A project with no existing lock file has nothing to diff against, so
    every locked package is considered new.

    Args:
        command: A normalized `add`/`update` `poetry` command.

    Returns:
        The `(name, version)` source map of packages newly added to or changed in
        the resulting `poetry.lock`, relative to the project's existing one (if any).

    Raises:
        subprocess.CalledProcessError: The command failed to resolve dependencies.
    """
    project_dir = _resolve_project_dir(command)

    with TemporaryPoetryProject(project_dir) as temp_dir:
        lock_path = temp_dir / "poetry.lock"
        old_map = _parse_lock_file(lock_path) if lock_path.is_file() else {}

        lock_command = _strip_directory_flag(command) + ["--lock"]
        subprocess.run(lock_command, cwd=temp_dir, check=True, text=True, capture_output=True)

        new_map = _parse_lock_file(lock_path) if lock_path.is_file() else {}
        return {key: source for key, source in new_map.items() if key not in old_map}


def _resolve_project_dir(command: list[str]) -> Path:
    """
    Locate the project directory referenced by a `poetry` `command`, via its
    `--directory`/`-C` flag if present, falling back to the current working directory.
    """
    for flag in ("--directory", "-C"):
        try:
            return Path(command[command.index(flag) + 1])
        except (ValueError, IndexError):
            pass
    return Path.cwd()


def _strip_directory_flag(command: list[str]) -> list[str]:
    """
    Remove any `--directory`/`-C` flag and its argument from `command`, so it can be
    safely re-run in a different project directory via the `cwd` argument.
    """
    stripped = list(command)
    for flag in ("--directory", "-C"):
        if flag in stripped:
            i = stripped.index(flag)
            del stripped[i:i + 2]
    return stripped


class TemporaryPoetryProject:
    """
    Prepares a temporary copy of a Poetry project's `pyproject.toml` (and `poetry.toml`
    + `poetry.lock`, if present), allowing `poetry` commands that write the lock file
    to run against the copy without affecting the original project.
    """
    def __init__(self, project_dir: Path):
        """
        Initialize a new `TemporaryPoetryProject`.

        Args:
            project_dir: Path to the project directory containing `pyproject.toml`.
        """
        self._project_dir = project_dir
        self._temp_dir: Optional[TemporaryDirectory] = None

    def __enter__(self) -> Path:
        """
        Set up the temporary project.

        Returns:
            The `Path` to the temporary project directory.
        """
        self._temp_dir = TemporaryDirectory()
        temp_path = Path(self._temp_dir.name)
        _log.debug("Created temporary poetry project directory %s for %s", temp_path, self._project_dir)

        try:
            shutil.copy(self._project_dir / "pyproject.toml", temp_path / "pyproject.toml")
            for optional_file in ("poetry.toml", "poetry.lock"):
                if (src := self._project_dir / optional_file).is_file():
                    shutil.copy(src, temp_path / optional_file)
                    _log.debug("Copied %s into temporary poetry project directory %s", src, temp_path)
        except Exception:
            _log.debug("Failed to set up temporary poetry project directory %s", temp_path, exc_info=True)
            self._temp_dir.cleanup()
            self._temp_dir = None
            raise

        return temp_path

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        if self._temp_dir:
            _log.debug("Cleaning up temporary poetry project directory %s", self._temp_dir.name)
            self._temp_dir.cleanup()
            self._temp_dir = None


def _parse_lock_file(lock_path: Path) -> dict[tuple[str, str], LocalPackageSource | RemotePackageSource]:
    """
    Parse a `poetry.lock` file and return a mapping from `(name, version)` to
    the package's source.

    Packages with a `[package.source]` of type `"directory"` or `"file"` are
    mapped to a `LocalPackageSource`. Packages with any other source type are
    mapped to the source URL as a `RemotePackageSource`. Packages with no source
    entry are assumed to come from PyPI and mapped to their canonical project page URL.

    Args:
        lock_path: Path to the `poetry.lock` file to parse.

    Returns:
        A `dict` mapping `(name, version)` pairs to package source objects.

    Raises:
        FileNotFoundError: `lock_path` does not exist.
        tomllib.TOMLDecodeError: The lock file is not valid TOML.
    """
    with open(lock_path, "rb") as f:
        lock_data = tomllib.load(f)

    source_map: dict[tuple[str, str], LocalPackageSource | RemotePackageSource] = {}
    for package in lock_data.get("package", []):
        name = package.get("name", "")
        version = package.get("version", "")
        if not name or not version:
            continue

        if source := package.get("source"):
            url = source.get("url")
            if source.get("type") in {"directory", "file"} and url:
                source_map[(name, version)] = LocalPackageSource(Path(url))
            elif url:
                source_map[(name, version)] = RemotePackageSource(url)
        else:
            source_map[(name, version)] = RemotePackageSource(
                f"{_PYPI_PROJECT_BASE_URL}/{name}/{version}/"
            )
    _log.debug("Parsed lock file %s into source map %s", lock_path, source_map)
    return source_map
