"""
Tests of the Supply-Chain Firewall command-line interface.
"""

import pytest

from scfw.cli import _parse_command_line, _DEFAULT_LOG_LEVEL, Subcommand


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


@pytest.mark.parametrize(
        "target",
        ["go", "npm", "pip", "poetry"]
)
def test_cli_audit_basic_usage(target: str):
    """
    Test of basic audit command usage for the given package manager `target`.
    """
    argv = ["scfw", "audit", target]
    args, _ = _parse_command_line(argv)
    assert args is not None

    assert args.subcommand == Subcommand.Audit
    assert args.log_level == _DEFAULT_LOG_LEVEL

    assert args.package_manager == target
    assert args.executable is None


def test_cli_audit_no_options_no_command():
    """
    Invocation of the audit subcommand with no options or arguments.
    """
    argv = ["scfw", "audit"]
    args, _ = _parse_command_line(argv)
    assert args is None


def test_cli_audit_all_options_no_package_manager():
    """
    Invocation of the audit subcommand with all options and no package manager.
    """
    executable = "/path/to/executable"
    argv = ["scfw", "audit", "--executable", executable]
    args, _ = _parse_command_line(argv)
    assert args is None


def test_cli_audit_unknown_package_manager():
    """
    Invocation of the audit subcommand with an unknown package manager.
    """
    argv = ["scfw", "audit", "foo"]
    args, _ = _parse_command_line(argv)
    assert args is None


@pytest.mark.parametrize(
        "target",
        ["go", "npm", "pip", "poetry"]
)
def test_cli_audit_all_options_package_manager(target: str):
    """
    Invocation of an audit command with all options and the given package manager `target`.
    """
    executable = "/path/to/executable"
    argv = ["scfw", "audit", "--executable", executable, target]
    args, _ = _parse_command_line(argv)
    assert args is not None

    assert args.subcommand == Subcommand.Audit
    assert args.log_level == _DEFAULT_LOG_LEVEL

    assert args.package_manager == target
    assert args.executable == executable


def test_cli_configure_basic_usage():
    """
    Basic `configure` subcommand usage.
    """
    argv = ["scfw", "configure"]
    args, _ = _parse_command_line(argv)
    assert args is not None

    assert args.subcommand == Subcommand.Configure
    assert args.log_level == _DEFAULT_LOG_LEVEL

    assert not args.remove
    assert not args.alias_go
    assert not args.alias_npm
    assert not args.alias_pip
    assert not args.alias_poetry
    assert args.dd_agent_port is None
    assert args.dd_api_key is None
    assert args.dd_log_level is None
    assert args.scfw_home is None


@pytest.mark.parametrize(
        "option",
        [
            ["--alias-go"],
            ["--alias-npm"],
            ["--alias-pip"],
            ["--alias-poetry"],
            ["--dd-agent-port", "10365"],
            ["--dd-api-key", "foo"],
            ["--dd-log-level", "BLOCK"],
            ["--scfw-home", "foo"],
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
            ["go", "get", "github.com/aws/aws-sdk-go-v2"],
            ["npm", "install", "react"],
            ["pip", "install", "requests"],
            ["poetry", "add", "requests"],
        ]
)
def test_cli_run_basic_usage(command: list[str]):
    """
    Test of basic run command usage for the given package manager `command`.
    """
    argv = ["scfw", "run"] + command
    args, _ = _parse_command_line(argv)
    assert args is not None

    assert args.subcommand == Subcommand.Run
    assert args.log_level == _DEFAULT_LOG_LEVEL

    assert args.package_manager == argv[2]
    assert args.command == argv[2:]
    assert not args.allow_unsupported
    assert not args.dry_run
    assert not args.executable


def test_cli_run_all_options_no_command():
    """
    Invocation with all options and no arguments.
    """
    executable = "/usr/bin/python"
    argv = ["scfw", "run", "--executable", executable, "--dry-run", "--allow-unsupported"]
    args, _ = _parse_command_line(argv)
    assert args is None


@pytest.mark.parametrize(
        "command",
        [
            ["go", "get", "github.com/aws/aws-sdk-go-v2"],
            ["npm", "install", "react"],
            ["pip", "install", "requests"],
            ["poetry", "add", "requests"],
        ]
)
def test_cli_run_all_options_command(command: list[str]):
    """
    Invocation of a run command with all options and the given `command`.
    """
    executable = "/path/to/executable"
    argv = ["scfw", "run", "--executable", executable, "--dry-run", "--allow-unsupported"] + command
    args, _ = _parse_command_line(argv)
    assert args is not None

    assert args.subcommand == Subcommand.Run
    assert args.log_level == _DEFAULT_LOG_LEVEL

    assert args.package_manager == argv[6]
    assert args.command == argv[6:]
    assert args.allow_unsupported
    assert args.dry_run
    assert args.executable == executable


@pytest.mark.parametrize(
        "command",
        [
            ["go", "get", "github.com/aws/aws-sdk-go-v2"],
            ["npm", "install", "react"],
            ["pip", "install", "requests"],
            ["poetry", "install", "requests"],
        ]
)
def test_cli_run_package_manager_dry_run(command: list[str]):
    """
    Test that a `--dry-run` flag belonging to the package manager command
    is parsed correctly as such.
    """
    argv = ["scfw", "run"] + command + ["--dry-run"]
    args, _ = _parse_command_line(argv)
    assert args is not None

    assert args.subcommand == Subcommand.Run
    assert args.log_level == _DEFAULT_LOG_LEVEL

    assert args.package_manager == argv[2]
    assert args.command == argv[2:]
    assert not args.dry_run
    assert not args.executable


@pytest.mark.parametrize(
        "target,test",
        [
            ("go", "npm"),
            ("go", "pip"),
            ("go", "poetry"),
            ("npm", "go"),
            ("npm", "pip"),
            ("npm", "poetry"),
            ("pip", "go"),
            ("pip", "npm"),
            ("pip", "poetry"),
            ("poetry", "go"),
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
    assert args is not None

    assert args.package_manager == argv[2]
    assert args.command == argv[2:]
