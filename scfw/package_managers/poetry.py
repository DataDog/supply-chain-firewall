"""
Provides a `PackageManager` representation of `poetry`.
"""

import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Optional

try:
    import tomllib  # type: ignore[import-not-found]
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]

from packaging.version import InvalidVersion, Version, parse as version_parse

from scfw.ecosystem import ECOSYSTEM
from scfw.package import LocalPackageSource, Package, RemotePackageSource
from scfw.package_manager import PackageManager, UnsupportedVersionError

_log = logging.getLogger(__name__)

_PYPI_PROJECT_BASE_URL = "https://pypi.org/project"

MIN_POETRY_VERSION = version_parse("1.7.0")

INSPECTED_SUBCOMMANDS = {"add", "install", "sync", "update"}


class Poetry(PackageManager):
    """
    A `PackageManager` representation of `poetry`.
    """
    def __init__(self, executable: Optional[str] = None):
        """
        Initialize a new `Poetry` instance.

        Args:
            executable:
                An optional path in the local filesystem to the `poetry` executable to use.
                If not provided, this value is determined by the current environment.

        Raises:
            RuntimeError: A valid executable could not be resolved.
        """
        executable = executable if executable else shutil.which(self.name())
        if not executable:
            raise RuntimeError("Failed to resolve local Poetry executable: is Poetry installed?")
        if not os.path.isfile(executable):
            raise RuntimeError(f"Path '{executable}' does not correspond to a regular file")

        self._executable = executable

    @classmethod
    def name(cls) -> str:
        """
        Return the token for invoking `poetry` on the command line.
        """
        return "poetry"

    @classmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the ecosystem of packages managed by `poetry`.
        """
        return ECOSYSTEM.PyPI

    def executable(self) -> str:
        """
        Return the local filesystem path to the underlying `poetry` executable.
        """
        return self._executable

    def run_command(self, command: list[str]) -> int:
        """
        Run a `poetry` command.

        Args:
            command: A `list[str]` containing a `poetry` command to execute.

        Returns:
            An `int` return code describing the exit status of the executed `poetry` command.

        Raises:
            ValueError: The given `command` is empty or not a valid `poetry` command.
        """
        return subprocess.run(self._normalize_command(command)).returncode

    def resolve_install_targets(self, command: list[str]) -> set[Package]:
        """
        Resolve the installation targets of the given `poetry` command.

        Args:
            command:
                A `list[str]` representing a `poetry` command whose installation targets
                are to be resolved.

        Returns:
            A `set[Package]` representing the package targets that would be installed
            if `command` were run.

        Raises:
            ValueError: The given `command` is empty or not a valid `poetry` command.
            UnsupportedVersionError: The underlying `poetry` executable is of an unsupported version.
        """
        def get_target_version(version_spec: str) -> str:
            _, arrow, new_version = version_spec.partition(" -> ")
            version, _, _ = version_spec.partition(' ')
            return get_target_version(new_version) if arrow else version

        def line_to_package(line: str) -> Optional[Package]:
            # All supported versions adhere to this format
            pattern = r"(Installing|Updating|Downgrading) (?:the current project: )?(.*) \((.*)\)"
            if "Skipped" not in line and (match := re.search(pattern, line.strip())):
                return Package(self.ecosystem(), match.group(2), get_target_version(match.group(3)))
            return None

        command = self._normalize_command(command)

        if not any(subcommand in command for subcommand in INSPECTED_SUBCOMMANDS):
            return set()

        self._check_version()

        # On supported versions, the presence of these options prevents the command from running
        if any(opt in command for opt in {"-V", "--version", "-h", "--help", "--dry-run"}):
            return set()

        try:
            # Compute installation targets: new dependencies and updates/downgrades of existing ones
            dry_run = subprocess.run(command + ["--dry-run"], check=True, text=True, capture_output=True)
            packages = set(filter(None, map(line_to_package, dry_run.stdout.split('\n'))))
        except subprocess.CalledProcessError:
            # An erroring command does not install anything
            _log.info("Encountered an error while resolving poetry installation targets")
            return set()

        if not packages:
            return packages

        source_map = _get_source_map(self._executable, command)
        return {
            Package(p.ecosystem, p.name, p.version, source_map.get((p.name, p.version)))
            for p in packages
        }

    def get_installed_packages(self) -> set[Package]:
        """
        Return the set of `PyPI` packages installed in the active `poetry` environment.

        Returns:
            A `set[Package]` representing all `PyPI` packages installed in the active
            `poetry` environment.

        Raises:
            RuntimeError: Failed to determine installed packages.
            ValueError: Malformed installed package report.
            UnsupportedVersionError: The underlying `poetry` executable is of an unsupported version.
        """
        def line_to_package(line: str) -> Package:
            tokens = line.split()
            return Package(ECOSYSTEM.PyPI, tokens[0], tokens[1])

        self._check_version()

        try:
            poetry_show_command = self._normalize_command(["poetry", "show", "--all"])
            poetry_show = subprocess.run(poetry_show_command, check=True, text=True, capture_output=True)
            installed_report = poetry_show.stdout.strip()
            return set(map(line_to_package, installed_report.split('\n'))) if installed_report else set()

        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to determine poetry installed packages")

        except IndexError:
            raise ValueError("Malformed installed package report")

    def _check_version(self):
        """
        Check whether the underlying `poetry` executable is of a supported version.

        Raises:
            UnsupportedVersionError: The underlying `poetry` executable is of an unsupported version.
        """
        def get_poetry_version(executable: str) -> Optional[Version]:
            try:
                # All supported versions adhere to this format
                poetry_version = subprocess.run([executable, "--version"], check=True, text=True, capture_output=True)
                match = re.search(r"Poetry \(version (.*)\)", poetry_version.stdout.strip())
                return version_parse(match.group(1)) if match else None
            except InvalidVersion:
                return None

        poetry_version = get_poetry_version(self._executable)
        if not poetry_version or poetry_version < MIN_POETRY_VERSION:
            raise UnsupportedVersionError(f"Poetry before v{MIN_POETRY_VERSION} is not supported")

    def _normalize_command(self, command: list[str]) -> list[str]:
        """
        Normalize a `poetry` command.

        Args:
            command: A `list[str]` containing a `poetry` command line.

        Returns:
            The equivalent but normalized form of `command` with the initial `poetry`
            token replaced with the local filesystem path to `self.executable()`.

        Raises:
            ValueError: The given `command` is empty or not a valid `poetry` command.
        """
        if not command:
            raise ValueError("Received empty poetry command line")
        if command[0] != self.name():
            raise ValueError("Received invalid poetry command line")

        return [self._executable] + command[1:]


def _get_source_map(
    executable: str, command: list[str]
) -> dict[tuple[str, str], LocalPackageSource | RemotePackageSource]:
    """
    Return a `(name, version)` source mapping for the project referenced by `command`.

    Locates the project directory via the `--directory`/`-C` flag in `command`,
    falling back to the current working directory. If a `poetry.lock` already
    exists there it is parsed directly; otherwise a `TemporaryPoetryProject` is
    used to generate one first.

    Returns an empty dict (and logs a warning) on any failure so callers can
    degrade gracefully to returning packages without source information.
    """
    for flag in ("--directory", "-C"):
        try:
            project_dir = Path(command[command.index(flag) + 1])
            break
        except (ValueError, IndexError):
            pass
    else:
        project_dir = Path.cwd()

    try:
        lock_path = project_dir / "poetry.lock"
        if lock_path.is_file():
            return _parse_lock_file(lock_path)

        with TemporaryPoetryProject(executable, project_dir) as generated_lock:
            return _parse_lock_file(generated_lock) if generated_lock else {}

    except Exception as e:
        _log.warning("Could not determine package sources from poetry.lock: %s", e, exc_info=True)
        return {}


class TemporaryPoetryProject:
    """
    Prepares a temporary Poetry project that duplicates a given one, allowing a
    `poetry.lock` file to be generated without modifying the original project.
    """
    def __init__(self, executable: str, project_dir: Path):
        """
        Initialize a new `TemporaryPoetryProject`.

        Args:
            executable: Path to the `poetry` executable.
            project_dir: Path to the project directory containing `pyproject.toml`.
        """
        self._executable = executable
        self._project_dir = project_dir
        self._temp_dir: Optional[TemporaryDirectory] = None

    def __enter__(self) -> Optional[Path]:
        """
        Set up the temporary project and generate a `poetry.lock` file.

        Returns:
            The `Path` to the generated `poetry.lock`, or `None` if generation failed.
        """
        self._temp_dir = TemporaryDirectory()
        temp_path = Path(self._temp_dir.name)

        shutil.copy(self._project_dir / "pyproject.toml", temp_path / "pyproject.toml")
        if (poetry_toml := self._project_dir / "poetry.toml").is_file():
            shutil.copy(poetry_toml, temp_path / "poetry.toml")

        _log.warning("No poetry.lock found; generating one in a temporary directory (this may be slow)")

        result = subprocess.run(
            [self._executable, "lock"],
            cwd=temp_path,
            text=True,
            capture_output=True,
        )
        lock_path = temp_path / "poetry.lock"
        if result.returncode != 0 or not lock_path.is_file():
            _log.warning(
                "Failed to generate poetry.lock in temporary directory (rc=%s): %s",
                result.returncode,
                (result.stderr or result.stdout).strip(),
            )
            return None

        return lock_path

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        if self._temp_dir:
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
            url = source.get("url", "")
            if source.get("type") in {"directory", "file"}:
                source_map[(name, version)] = LocalPackageSource(Path(url))
            elif url:
                source_map[(name, version)] = RemotePackageSource(url)
        else:
            source_map[(name, version)] = RemotePackageSource(
                f"{_PYPI_PROJECT_BASE_URL}/{name}/{version}/"
            )

    return source_map
