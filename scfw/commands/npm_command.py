"""
Defines a subclass of `PackageManagerCommand` for `npm` commands.
"""

import logging
import os
import shutil
import subprocess
from typing import Optional

from packaging.version import InvalidVersion, Version, parse as version_parse

from scfw.command import PackageManagerCommand, UnsupportedVersionError
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget

_log = logging.getLogger(__name__)

MIN_NPM_VERSION = version_parse("7.0.0")

_UNSUPPORTED_NPM_VERSION = f"npm before v{MIN_NPM_VERSION} is not supported"

# The "placeDep" log lines describe a new dependency added to the
# dependency tree being constructed by an installish command
_NPM_LOG_PLACE_DEP = "placeDep"

# Each added dependency is always the fifth token in its log line
_NPM_LOG_DEP_TOKEN = 4


class NpmCommand(PackageManagerCommand):
    """
    A representation of `npm` commands via the `PackageManagerCommand` interface.
    """
    def __init__(self, command: list[str], executable: Optional[str] = None):
        """
        Initialize a new `NpmCommand`.

        Args:
            command: An `npm` command line.
            executable:
                Optional path to the executable to run the command.  Determined by the
                environment if not given.

        Raises:
            ValueError: An invalid `npm` command was given.
            RuntimeError: A valid executable could not be resolved.
            UnsupportedVersionError:
                An unsupported version of `npm` was used to initialize an `NpmCommand`.
        """
        def get_npm_version(executable) -> Version:
            try:
                # All supported versions adhere to this format
                npm_version_command = [executable, "--version"]
                version_str = subprocess.run(npm_version_command, check=True, text=True, capture_output=True)
                return version_parse(version_str.stdout.strip())
            except InvalidVersion:
                raise UnsupportedVersionError(_UNSUPPORTED_NPM_VERSION)

        if not command or command[0] != "npm":
            raise ValueError("Malformed npm command")

        executable = executable if executable else shutil.which("npm")
        if not executable:
            raise RuntimeError("Failed to resolve local npm executable")
        if not os.path.isfile(executable):
            raise RuntimeError(f"Path '{executable}' does not correspond to a regular file")

        if get_npm_version(executable) < MIN_NPM_VERSION:
            raise UnsupportedVersionError(_UNSUPPORTED_NPM_VERSION)

        self._command = command.copy()
        self._command[0] = executable

    @classmethod
    def name(cls) -> str:
        """
        Return the token for invoking `npm` on the command line.
        """
        return "npm"

    @classmethod
    def ecosystem(cls) -> ECOSYSTEM:
        """
        Return the ecosystem of `npm` commands.
        """
        return ECOSYSTEM.Npm

    def executable(self) -> str:
        """
        Query the npm executable for an `npm` command.
        """
        return self._command[0]

    def run(self):
        """
        Run an `npm` command.
        """
        subprocess.run(self._command)

    def would_install(self) -> list[InstallTarget]:
        """
        Determine the package release targets an `npm` command would install if it were run.

        Returns:
            A `list[InstallTarget]` representing the package release targets the `npm` command
            would install if it were run.

        Raises:
            ValueError: The `npm` dry-run output does not have the expected format.
        """
        def is_place_dep_line(line: str) -> bool:
            return _NPM_LOG_PLACE_DEP in line

        def line_to_dependency(line: str) -> str:
            return line.split()[_NPM_LOG_DEP_TOKEN]

        def str_to_install_target(s: str) -> InstallTarget:
            package, sep, version = s.rpartition('@')
            if version == s or (sep and not package):
                raise ValueError("Failed to parse npm install target")
            return InstallTarget(ECOSYSTEM.Npm, package, version)

        # For now, automatically allow all non-`install` commands
        if not self._is_install_command():
            return []

        # The presence of these options prevent the install command from running
        if any(opt in self._command for opt in {"-h", "--help", "--dry-run"}):
            return []

        try:
            # Compute the set of dependencies added by the install command
            dry_run_command = self._command + ["--dry-run", "--loglevel", "silly"]
            dry_run = subprocess.run(dry_run_command, check=True, text=True, capture_output=True)
            dependencies = map(line_to_dependency, filter(is_place_dep_line, dry_run.stderr.strip().split('\n')))
        except subprocess.CalledProcessError:
            # An erroring command does not install anything
            _log.info("The npm command encountered an error while collecting installation targets")
            return []

        try:
            # List targets already installed in the npm environment
            list_command = [self.executable(), "list", "--all"]
            installed = subprocess.run(list_command, check=True, text=True, capture_output=True).stdout
        except subprocess.CalledProcessError:
            # If this operation fails, rather than blocking, assume nothing is installed
            # This has the effect of treating all dependencies like installation targets
            _log.warning(
                "Failed to list installed npm packages: treating all dependencies as installation targets"
            )
            installed = ""

        # The installation targets are the dependencies that are not already installed
        targets = filter(lambda dep: dep not in installed, dependencies)

        return list(map(str_to_install_target, targets))

    def _is_install_command(self) -> bool:
        """
        Determine whether the underlying `npm` command is for an `install` subcommand.

        Returns:
            A `bool` indicating whether the `npm` command underlying the given `NpmCommand`
            is likely for an `install` subcommand.

            This function gives no false negatives but may give false positives. False
            positives are safe in this case because they result in non-installish
            commands being analyzed as if they were installish commands. To eliminate
            false positives, we would need to write a full parser for npm.
        """
        # https://docs.npmjs.com/cli/v10/commands/npm-install
        install_aliases = {
            "install", "add", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall"
        }

        return any(alias in self._command for alias in install_aliases)
