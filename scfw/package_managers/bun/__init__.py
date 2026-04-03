"""
Provides a `PackageManager` representation of `bun`.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Optional

from packaging.version import InvalidVersion, Version
from packaging.version import parse as version_parse

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_manager import PackageManager, UnsupportedVersionError

_log = logging.getLogger(__name__)

MIN_BUN_VERSION = version_parse("1.0.0")


class Bun(PackageManager):
    """
    A `PackageManager` representation of `bun`.
    """

    def __init__(self, executable: Optional[str] = None):
        """
        Initialize a new `Bun` instance.

        Args:
            executable:
                An optional path in the local filesystem to the `bun` executable to use.
                If not provided, this value is determined by the current environment.

        Raises:
            RuntimeError: A valid executable could not be resolved.
        """
        executable = executable if executable else shutil.which(self.name())
        if not executable:
            raise RuntimeError(
                "Failed to resolve local Bun executable: is Bun installed?"
            )
        if not os.path.isfile(executable):
            raise RuntimeError(
                f"Path '{executable}' does not correspond to a regular file"
            )

        self._executable = executable
        self._check_version()

    @classmethod
    def name(cls) -> str:
        """
        Return the token for invoking `bun` on the command line.
        """
        return "bun"

    @classmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the ecosystem of packages managed by `bun`.
        """
        return ECOSYSTEM.Bun

    def executable(self) -> str:
        """
        Return the local filesystem path to the underlying `bun` executable.
        """
        return self._executable

    def run_command(self, command: list[str]) -> int:
        """
        Run a `bun` command.

        Args:
            command: A `list[str]` containing a `bun` command to execute.

        Returns:
            An `int` return code describing the exit status of the executed `bun` command.

        Raises:
            ValueError: The given `command` is empty or not a valid `bun` command.
        """
        return subprocess.run(self._normalize_command(command)).returncode

    def resolve_install_targets(self, command: list[str]) -> list[Package]:
        """
        Resolve the installation targets of the given `bun` command.

        Args:
            command:
                A `list[str]` representing a `bun` command whose installation targets
                are to be resolved.

        Returns:
            A `list[Package]` representing the package targets that would be installed
            if `command` were run.

        Raises:
            ValueError: The given `command` is empty or not a valid `bun` command
            UnsupportedVersionError: The underlying `bun` executable is of an unsupported version.
        """

        def is_install_command(command: list[str]) -> bool:
            # https://bun.com/docs/cli/install
            install_aliases = {"install", "i", "add", "a"}
            return any(alias in command for alias in install_aliases)

        if not command or command[0] != self.name():
            raise ValueError("Received empty or invalid bun command")

        # For now, allow all non-`install` commands
        if not is_install_command(command):
            return []

        # Respect help flag but not dry-run (dry-run is needed for parsing)
        if any(opt in command for opt in {"-h", "--help"}):
            return []

        try:
            return self._resolve_install_targets_command(command)

        except Exception as e:
            _log.info(f"Failed to resolve bun installation targets: {e}")
            return []

    def list_installed_packages(self) -> list[Package]:
        """
        List all `bun` packages installed in the active `bun` environment.

        Returns:
            A `list[Package]` representing all `bun` packages installed in the active
            `bun` environment.

        Raises:
            RuntimeError: Failed to list installed packages.
            ValueError: Encountered a malformed output format.
        """

        def parse_package_line(line: str) -> Optional[Package]:
            """
            Parse a single line from bun's list output.

            bun list output format (tree):
                ├── package-name@version
                │   ├── dependency@version
                │   └── ...

            bun list output format (flat):
                package-name@version
            """
            # Remove tree characters and whitespace
            cleaned = line.strip()

            # Skip empty lines
            if not cleaned:
                return None

            # Remove ASCII tree characters: ├─, └─, ─, │
            cleaned = cleaned.replace("├──", "").replace("└──", "").strip()
            cleaned = cleaned.replace("│", "").strip()

            # Remove any remaining leading/trailing whitespace
            cleaned = cleaned.strip()

            if not cleaned:
                return None

            # Parse package@version
            if "@" not in cleaned:
                return None

            name, sep, version = cleaned.partition("@")
            if not (name and sep and version):
                return None

            return Package(ECOSYSTEM.Bun, name, version)

        try:
            list_command = [self._executable, "list", "--all"]
            # Run in current working directory to find package.json
            result = subprocess.run(
                list_command,
                check=True,
                text=True,
                capture_output=True,
                cwd=os.getcwd(),
            )
            output = result.stdout.strip()

            if not output:
                return []

            packages = []
            for line in output.split("\n"):
                if pkg := parse_package_line(line):
                    packages.append(pkg)

            return packages

        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to list bun installed packages")

    def _check_version(self):
        """
        Check whether the underlying `bun` executable is of a supported version.

        Raises:
            UnsupportedVersionError: The underlying `bun` executable is of an unsupported version.
        """

        def get_bun_version(executable: str) -> Optional[Version]:
            try:
                version_output = subprocess.run(
                    [executable, "--version"],
                    check=True,
                    text=True,
                    capture_output=True,
                )
                # bun version format: "1.3.8+b64edcb49" or "1.3.8"
                # Extract the base version number
                version_str = version_output.stdout.strip()
                # Split on '+' or '-' to get base version
                base_version = version_str.split("+")[0].split("-")[0]
                return version_parse(base_version)
            except InvalidVersion:
                return None

        bun_version = get_bun_version(self._executable)
        if not bun_version or bun_version < MIN_BUN_VERSION:
            raise UnsupportedVersionError(
                f"bun before v{MIN_BUN_VERSION} is not supported"
            )

    def _resolve_install_targets_command(self, command: list[str]) -> list[Package]:
        """
        Resolve installation targets using bun's dry-run mode.

        Args:
            command: Normalized bun install/add command

        Returns:
            List of Package objects to be installed
        """
        # Run bun with dry-run to get verbose installation list
        dry_run_command = command + ["--dry-run"]
        result = subprocess.run(
            dry_run_command, check=True, text=True, capture_output=True, cwd=os.getcwd()
        )

        # Parse bun dry-run output from stdout
        # Example output:
        # bun add v1.3.8 (b64edcb49)
        # @types/bun@1.3.11
        # form-data@4.0.5
        # ...
        # installed zod@4.3.6
        #
        # [421.00ms] done
        output = result.stdout.strip() if result.stdout else ""

        if not output:
            return []

        packages = []
        for line in output.split("\n"):
            line = line.strip()

            # Skip empty lines and completion lines
            if not line or line.endswith("ms] done") or line.startswith("bun v"):
                continue

            # Match "installed package@version" line (this is the target package being added)
            if line.startswith("installed "):
                installed_part = line.split(" ", 1)[
                    1
                ]  # Get everything after "installed "
                pkg = parse_package_for_version(installed_part)
                if pkg:
                    packages.append(pkg)

        return packages

    def _normalize_command(self, command: list[str]) -> list[str]:
        """
        Normalize a `bun` command.

        Args:
            command: A `list[str]` containing a `bun` command line.

        Returns:
            The equivalent but normalized form of `command` with the initial `bun`
            token replaced with the local filesystem path to `self.executable()`.

        Raises:
            ValueError: The given `command` is empty or not a valid `bun` command.
        """
        if not command:
            raise ValueError("Received empty bun command line")
        if command[0] != self.name():
            raise ValueError("Received invalid bun command line")

        return [self._executable] + command[1:]


def parse_package_for_version(spec: str) -> Optional[Package]:
    """
    Parse a package specification string into a Package.

    Args:
        spec: Package specification like "package@1.0.0"

    Returns:
        A Package object if parsing succeeds, None otherwise
    """
    if "@" not in spec:
        return None

    name, sep, version = spec.partition("@")
    if not (name and sep and version):
        return None

    return Package(ECOSYSTEM.Bun, name, version)


def find_package_specs(text: str) -> list[str]:
    """
    Find all package@version patterns in text.

    Args:
        text: Text to search in

    Returns:
        List of package@version strings found
    """
    import re

    # Match package names and versions
    # Package names can contain alphanumerics, hyphens, underscores, @ for scope
    pattern = r"(@[a-zA-Z0-9_/-]+/[a-zA-Z0-9_/-]+|@?[a-zA-Z0-9_/-]+)@([0-9]+\.[0-9]+\.[0-9]+|@\w+|\^?[0-9]+\.[0-9]+\.[0-9]+)"
    matches = re.findall(pattern, text)
    return [f"{name}{sep}{version}" for name, sep, version in matches]
