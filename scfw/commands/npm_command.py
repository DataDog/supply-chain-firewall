"""
Defines a subclass of `PackageManagerCommand` for `npm` commands.
"""

import logging
import subprocess
from typing import Optional

from packaging.version import InvalidVersion, Version, parse as version_parse

from scfw.command import PackageManagerCommand, UnsupportedVersionError
from scfw.ecosystem import ECOSYSTEM
from scfw.parser import ArgumentError, ArgumentParser
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
        self._command = command
        self._executable = "npm"

        if executable:
            self._command[0] = self._executable = executable
        if get_npm_version(self._executable) < MIN_NPM_VERSION:
            raise UnsupportedVersionError(_UNSUPPORTED_NPM_VERSION)

    def run(self):
        """
        Run an `npm` command.
        """
        subprocess.run(self._command)

    def would_install(self) -> list[InstallTarget]:
        """
        Determine the list of packages an `npm` command would install if it were run.

        Returns:
            A `list[InstallTarget]` representing the packages the `npm` command would
            install if it were run.

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
            return InstallTarget(ECOSYSTEM.NPM, package, version)

        # Help options always take precedence: nothing will be installed
        # The presence of `--dry-run` should prevent installations from occurring
        if any(opt in self._command for opt in {"-h", "--help", "--dry-run"}):
            return []

        if (init_command := self._get_init_command()):
            try:
                args = _npm_init_cli().parse_args(init_command[1:])
                if not args.initializer:
                    return []
                # Isolate and analyze the installation portion of the init command
                # All but the first initializer tokens provided to npm are ignored
                proxy_command = NpmCommand(
                    ["npm", "install", _init_install_target(args.initializer[0])],
                    executable=self._executable
                )
                return proxy_command.would_install()
            except ArgumentError:
                _log.info("The npm init command encountered an error while parsing")
                return []

        try:
            # Compute the set of dependencies added by the command
            # This is a superset of the set of install targets
            dry_run_command = self._command + ["--dry-run", "--loglevel", "silly"]
            dry_run = subprocess.run(dry_run_command, check=True, text=True, capture_output=True)
            dependencies = map(line_to_dependency, filter(is_place_dep_line, dry_run.stderr.strip().split('\n')))
        except subprocess.CalledProcessError:
            # An error must have resulted from the given npm command
            # As nothing will be installed in this case, allow the command
            _log.info("The npm command encountered an error while collecting installation targets")
            return []

        try:
            # List targets already installed in the npm environment
            list_command = [self._executable, "list", "--all"]
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

    def _get_init_command(self) -> Optional[list[str]]:
        """
        Determine whether the `NpmCommand` is for an `npm init` command.

        Returns:
            The command line for the `npm init` subcommand, in the case that the
            `NpmCommand` does indeed correspond to such a command.  If not, `None`
            is returned.

            Note that the first token in the returned command line is `init` or
            one of its aliases.

            Options intended to be passed to the command to be executed (i.e., those
            following the `--` separator) are excluded. Thus, the returned command
            line contains exactly what is relevant to the `npm init` command.
        """
        start = stop = -1

        # https://docs.npmjs.com/cli/v10/commands/npm-init
        for i, token in enumerate(self._command):
            if start < 0 and token in {"create", "init", "innit"}:
                start = i
            if stop < 0 and token == "--":
                stop = i
                break

        if start < 0:
            return None

        if stop > start:
            return self._command[start:stop]

        return self._command[start:]


def _npm_init_cli() -> ArgumentParser:
    """
    Return an `ArgumentParser` for the `npm init` command line.

    Returns:
        The static parser for the `npm init` command line.
    """
    parser = ArgumentParser(exit_on_error=False)

    # https://docs.npmjs.com/cli/v10/commands/npm-init
    parser.add_argument("initializer", type=str, default=None, nargs="*")
    parser.add_argument("--init-author-name", type=str, default=None)
    parser.add_argument("--init-author-url", type=str, default=None)
    parser.add_argument("--init-licence", type=str, default=None)
    parser.add_argument("--init-module", type=str, default=None)
    parser.add_argument("--init-version", type=str, default=None)
    parser.add_argument("--scope", type=str, default=None)
    parser.add_argument("-w", "--workspace", type=str, nargs='+', default=[])
    parser.add_argument("-y", "--yes", action="store_true")
    parser.add_argument("-f", "--force", action="store_true")
    parser.add_argument("-ws", "--workspaces", action="store_true")
    parser.add_argument("--no-workspaces-update", action="store_true")
    parser.add_argument("--include-workspace-root", action="store_true")

    return parser


def _init_install_target(initializer: str) -> str:
    """
    Generate the installation target name for the given `npm init` initializer.

    Args:
        initializer: The `npm init` initializer string to be transformed.

    Returns:
        The installation target name corresponding to the input initializer.
    """
    # https://docs.npmjs.com/cli/v10/commands/npm-init
    def target_name(initializer: str) -> str:
        return f"create-{initializer}" if initializer else "create"

    if initializer.startswith('@'):
        components = initializer.split('/', 1)
        if len(components) == 1:
            prefix, _, suffix = components[0].rpartition('@')
            if not prefix:
                return f"{components[0]}/{target_name('')}"
            return f"{components[0]}/{target_name('')}@{suffix}"
        return f"{components[0]}/{target_name(components[1])}"

    return target_name(initializer)
