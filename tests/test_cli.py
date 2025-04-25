"""
Tests of the Supply-Chain Firewall command-line interface.
"""

import pytest

from scfw.cli import _parse_command_line, _DEFAULT_LOG_LEVEL


def test_cli_no_options_no_command():
    """
    Invocation with no options or arguments.
    """
    argv = ["scfw"]
    args, _ = _parse_command_line(argv)
    assert args is None


def test_cli_all_options_no_command():
    """
    Invocation with all top-level options and no subcommand.
    """
    argv = ["scfw", "--log-level", "DEBUG"]
    args, _ = _parse_command_line(argv)
    assert args is None


def test_cli_incorrect_subcommand():
    """
    Invocation with a nonexistent subcommand.
    """
    argv = ["scfw", "nonexistent"]
    args, _ = _parse_command_line(argv)
    assert args is None


def test_cli_all_options_no_command():
    """
    Invocation with all options and no arguments.
    """
    executable = "/usr/bin/python"
    argv = ["scfw", "run", "--executable", executable, "--dry-run"]
    args, _ = _parse_command_line(argv)
    assert args is None


def test_cli_basic_usage_configure():
    """
    Basic `configure` subcommand usage.
    """
    argv = ["scfw", "configure"]
    args, _ = _parse_command_line(argv)
    assert args.subcommand == "configure"
    assert "command" not in args
    assert "dry_run" not in args
    assert "executable" not in args
    assert args.log_level == _DEFAULT_LOG_LEVEL


@pytest.mark.parametrize(
        "option",
        [
            ["--alias-npm"],
            ["--alias-pip"],
            ["--alias-poetry"],
            ["--dd-agent-port", "10365"],
            ["--dd-api-key", "foo"],
            ["--dd-log-level", "BLOCK"],

        ]
)
def test_cli_configure_removal(option: list[str]):
    """
    Test that the `--remove` configure option is not allowed with `option`.
    """
    argv = ["scfw", "configure", "--remove"] + option
    args, _ = _parse_command_line(argv)
    assert args is None


@pytest.mark.parametrize(
        "command",
        [
            ["npm", "install", "react"],
            ["pip", "install", "requests"],
            ["poetry", "add", "requests"],
        ]
)
def test_cli_basic_usage_run(command: list[str]):
    """
    Test of basic run command usage for the given package manager `command`.
    """
    argv = ["scfw", "run"] + command
    args, _ = _parse_command_line(argv)
    assert args.subcommand == "run"
    assert args.command == argv[2:]
    assert not args.dry_run
    assert not args.executable
    assert args.log_level == _DEFAULT_LOG_LEVEL


@pytest.mark.parametrize(
        "command",
        [
            ["npm", "install", "react"],
            ["pip", "install", "requests"],
            ["poetry", "add", "requests"],
        ]
)
def test_cli_all_options_run_command(command: list[str]):
    """
    Invocation of a run command with all options and the given `command`.
    """
    executable = "/path/to/executable"
    argv = ["scfw", "run", "--executable", executable, "--dry-run"] + command
    args, _ = _parse_command_line(argv)
    assert args.subcommand == "run"
    assert args.command == argv[5:]
    assert args.dry_run
    assert args.executable == executable
    assert args.log_level == _DEFAULT_LOG_LEVEL


@pytest.mark.parametrize(
        "command",
        [
            ["npm", "install", "react"],
            ["pip", "install", "requests"],
            ["poetry", "install", "requests"],
        ]
)
def test_cli_package_manager_dry_run(command: list[str]):
    """
    Test that a `--dry-run` flag belonging to the package manager command
    is parsed correctly as such.
    """
    argv = ["scfw", "run"] + command + ["--dry-run"]
    args, _ = _parse_command_line(argv)
    assert args.subcommand == "run"
    assert args.command == argv[2:]
    assert not args.dry_run
    assert not args.executable
    assert args.log_level == _DEFAULT_LOG_LEVEL


@pytest.mark.parametrize(
        "target,test",
        [
            ("npm", "pip"),
            ("npm", "poetry"),
            ("pip", "npm"),
            ("pip", "poetry"),
            ("poetry", "npm"),
            ("poetry", "pip"),
        ]
)
def test_cli_run_priority(target: str, test: str):
    """
    Test that a `target` command is parsed correctly in the presence of a `test` literal.
    """
    argv = ["scfw", "run", target, "foo", test]
    args, _ = _parse_command_line(argv)
    assert args.command == argv[2:]
