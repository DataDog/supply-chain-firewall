from scfw.cli import _parse_command_line, _DEFAULT_LOG_LEVEL


def test_cli_basic_usage_pip():
    """
    Basic pip command usage.
    """
    argv = ["scfw", "run", "pip", "install", "requests"]
    args, _ = _parse_command_line(argv)
    assert args.subcommand == "run"
    assert args.command == argv[2:]
    assert not args.dry_run
    assert not args.executable
    assert args.log_level == _DEFAULT_LOG_LEVEL


def test_cli_basic_usage_npm():
    """
    Basic npm command usage.
    """
    argv = ["scfw", "run", "npm", "install", "react"]
    args, _ = _parse_command_line(argv)
    assert args.subcommand == "run"
    assert args.command == argv[2:]
    assert not args.dry_run
    assert not args.executable
    assert args.log_level == _DEFAULT_LOG_LEVEL


def test_cli_no_options_no_command():
    """
    Invocation with no options or arguments.
    """
    argv = ["scfw"]
    args, _ = _parse_command_line(argv)
    assert args.subcommand == None
    assert "command" not in args
    assert "dry_run" not in args
    assert "executable" not in args
    assert args.log_level == _DEFAULT_LOG_LEVEL


def test_cli_all_options_no_command():
    """
    Invocation with all options and no arguments.
    """
    executable = "/usr/bin/python"
    argv = ["scfw", "run", "--executable", executable, "--dry-run"]
    args, _ = _parse_command_line(argv)
    assert args == None


def test_cli_all_options_pip():
    """
    Invocation with all options and a pip command argument.
    """
    executable = "/usr/bin/python"
    argv = ["scfw", "run", "--executable", executable, "--dry-run", "pip", "install", "requests"]
    args, _ = _parse_command_line(argv)
    assert args.subcommand == "run"
    assert args.command == argv[5:]
    assert args.dry_run
    assert args.executable == executable
    assert args.log_level == _DEFAULT_LOG_LEVEL


def test_cli_all_options_npm():
    """
    Invocation with all options and an npm command argument.
    """
    executable = "/opt/homebrew/bin/npm"
    argv = ["scfw", "run", "--executable", executable, "--dry-run", "npm", "install", "react"]
    args, _ = _parse_command_line(argv)
    assert args.subcommand == "run"
    assert args.command == argv[5:]
    assert args.dry_run
    assert args.executable == executable
    assert args.log_level == _DEFAULT_LOG_LEVEL


def test_cli_package_manager_dry_run_pip():
    """
    Test that a pip `--dry-run` flag is parsed correctly as such.
    """
    argv = ["scfw", "run", "pip", "--dry-run", "install", "requests"]
    args, _ = _parse_command_line(argv)
    assert args.subcommand == "run"
    assert args.command == argv[2:]
    assert not args.dry_run
    assert not args.executable
    assert args.log_level == _DEFAULT_LOG_LEVEL


def test_cli_package_manager_dry_run_npm():
    """
    Test that an npm `--dry-run` flag is parsed correctly as such.
    """
    argv = ["scfw", "run", "npm", "--dry-run", "install", "react"]
    args, _ = _parse_command_line(argv)
    assert args.subcommand == "run"
    assert args.command == argv[2:]
    assert not args.dry_run
    assert not args.executable
    assert args.log_level == _DEFAULT_LOG_LEVEL


def test_cli_pip_over_npm():
    """
    Test that a pip command is parsed correctly in the presence of an "npm" literal.
    """
    argv = ["scfw", "run", "pip", "install", "npm"]
    args, _ = _parse_command_line(argv)
    assert args.command == argv[2:]


def test_cli_npm_over_pip():
    """
    Test that an npm command is parsed correctly in the presence of a "pip" literal.
    """
    argv = ["scfw", "run", "npm", "install", "pip"]
    args, _ = _parse_command_line(argv)
    assert args.command == argv[2:]
