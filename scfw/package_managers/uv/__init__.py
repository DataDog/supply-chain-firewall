"""
Provides a `PackageManager` representation of `uv`.
"""

import json
import logging
import os
import re
import shutil
import subprocess
from typing import Optional

from packaging.version import InvalidVersion, Version, parse as version_parse

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_manager import InstallTargetResolutionError, PackageManager, UnsupportedVersionError
from scfw.package_managers.uv.temp_project import TemporaryUvProject

_log = logging.getLogger(__name__)

MIN_UV_VERSION = version_parse("0.5.0")

INSPECTED_SUBCOMMANDS: set[str] = {
    "sync",
}


class Uv(PackageManager):
    """
    A `PackageManager` representation of `uv`.
    """
    def __init__(self, executable: Optional[str] = None):
        """
        Initialize a new `Uv` instance.

        Args:
            executable:
                An optional path in the local filesystem to the `uv` executable to use.
                If not provided, this value is determined by the current environment.

        Raises:
            RuntimeError: A valid executable could not be resolved.
        """
        executable = executable if executable else shutil.which(self.name())
        if not executable:
            raise RuntimeError("Failed to resolve local uv executable: is uv installed?")
        if not os.path.isfile(executable):
            raise RuntimeError(f"Path '{executable}' does not correspond to a regular file")

        self._executable = executable

    @classmethod
    def name(cls) -> str:
        """
        Return the token for invoking `uv` on the command line.
        """
        return "uv"

    @classmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the ecosystem of packages managed by `uv`.
        """
        return ECOSYSTEM.PyPI

    def executable(self) -> str:
        """
        Return the local filesystem path to the underlying `uv` executable.
        """
        return self._executable

    def run_command(self, command: list[str]) -> int:
        """
        Run a `uv` command.

        Args:
            command: A `list[str]` containing a `uv` command to execute.

        Returns:
            An `int` return code describing the exit status of the executed `uv` command.

        Raises:
            ValueError: The given `command` is empty or not a valid `uv` command.
        """
        return subprocess.run(self._normalize_command(command), check=False).returncode

    def resolve_install_targets(self, command: list[str]) -> set[Package]:
        """
        Resolve the installationj targets of the given `uv` command.

        For `uv sync`, the project's requirements are exported via `uv export` and pip
        is used to determine what packages would actually be installed.

        Args:
            command:
                A `list[str]` representing a `uv` command whose installation targets
                are to be resolved.

        Returns:
            A `set[Package]` representing the package targets that would be instlled
            if `command` were run.

        Raises:
            ValueError: The given `command` is empty or not a valid `uv` command.
            UnsupportedVersionError: The underlying `uv` executable is of an unsupported version.
        """
        normalized_command = self._normalize_command(command)
        if not any(subcommand in normalized_command for subcommand in INSPECTED_SUBCOMMANDS):
            return set()

        self._check_version()

        # https://docs.astral.sh/uv/reference/cli/
        common_flags: set[str] = {
            "-V",
            "--version",
            "-h",
            "--help",
            "--dry-run",
        }
        if any(opt in normalized_command for opt in common_flags):
            return set()

        try:
            with TemporaryUvProject(self._executable) as temp_project:
                return temp_project.resolve_via_export()
        except subprocess.CalledProcessError as e:
            _log.error(
                "Encountered an error while resolving uv installation targets: %s",
                (e.stderr or e.stdout or "").strip(),
                exc_info=True,
            )
            raise InstallTargetResolutionError("Failed to resolve uv installation targets") from e
        except Exception as e:
            _log.error(
                "Encountered an unexpected error while preparing temporary uv project: %s",
                str(e),
                exc_info=True,
            )
            raise InstallTargetResolutionError("Failed to prepare temporary uv project") from e

    def get_installed_packages(self) -> set[Package]:
        """
        Return the set of `PyPI` packages installed in the active `uv `environment.

        Returns:
            A `set[Package]` representing al `PyPI` packages installed in the active
            `uv` environment.

        Raises:
            RuntimeError: Failed to determine the installed packages.
            UnsupportedVersionError: The underlying `uv` executable is of an unsupported version.
        """
        self._check_version()

        try:
            uv_pip_list_command: list[str] = [self._executable, "pip", "list", "--format", "json"]
            result = subprocess.run(uv_pip_list_command, check=True, capture_output=True, text=True)

            entries = json.loads(result.stdout)
            return {
                Package(ECOSYSTEM.PyPI, entry["name"], entry["version"])
                for entry in entries
                if entry.get("name") and entry.get("version")
            }
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to determine uv installed packages")

    def _check_version(self):
        """
        Check whether the underlying `uv` executable is of a supported version.

        Raises:
            UnsupportedVersionError: The underlying `uv` executable is of an unsupported version.
        """
        def get_uv_version(executable: str) -> Optional[Version]:
            try:
                result = subprocess.run(
                    [executable, "--version"],
                    check=True,
                    text=True,
                    capture_output=True,
                )
                match = re.match(r"^uv\s+(\S+)", result.stdout.strip())
                if not match:
                    return None

                return version_parse(match.group(1))
            except (IndexError, InvalidVersion):
                return None

        uv_version = get_uv_version(self._executable)
        if not uv_version or uv_version < MIN_UV_VERSION:
            raise UnsupportedVersionError(f"uv before v{MIN_UV_VERSION} is not supported")

    def _normalize_command(self, command: list[str]) -> list[str]:
        """
        Normalize a `uv` command by replacing the `uv` token with the resolved executable path.

        Args:
            command: A `list[str]` containing a `uv` command (starting with `"uv"`).

        Returns:
            The normalized command with the executable path substituted for `"uv"`.

        Raises:
            ValueError: The given `command` is empty or not a valid `uv` command.
        """
        if not command:
            raise ValueError("Received empty uv command line")
        if command[0] != self.name():
            raise ValueError("Received invalid uv command line")

        return [self._executable] + command[1:]
