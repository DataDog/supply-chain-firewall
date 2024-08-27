from scfw.cli import _parse_command_line


def test_cli_basic_usage_pip():
    """
    Basic pip command usage.
    """
    argv = ["scfw", "pip", "install", "requests"]
    args, _ = _parse_command_line(argv)
    assert args.command == argv[1:]
    assert not args.dry_run
    assert not args.executable


def test_cli_basic_usage_npm():
    """
    Basic npm command usage.
    """
    argv = ["scfw", "npm", "install", "react"]
    args, _ = _parse_command_line(argv)
    assert args.command == argv[1:]
    assert not args.dry_run
    assert not args.executable


def test_cli_no_options_no_command():
    """
    Invocation with no options or arguments.
    """
    argv = ["scfw"]
    args, _ = _parse_command_line(argv)
    assert args.command == []
    assert not args.dry_run
    assert not args.executable


def test_cli_all_options_no_command():
    """
    Invocation with all options and no arguments.
    """
    executable = "/usr/bin/python"
    argv = ["scfw", "--executable", executable, "--dry-run"]
    args, _ = _parse_command_line(argv)
    assert args.command == []
    assert args.dry_run
    assert args.executable == executable


def test_cli_all_options_pip():
    """
    Invocation with all options and a pip command argument.
    """
    executable = "/usr/bin/python"
    argv = ["scfw", "--executable", executable, "--dry-run", "pip", "install", "requests"]
    args, _ = _parse_command_line(argv)
    assert args.command == argv[4:]
    assert args.dry_run
    assert args.executable == executable


def test_cli_all_options_npm():
    """
    Invocation with all options and an npm command argument.
    """
    executable = "/opt/homebrew/bin/npm"
    argv = ["scfw", "--executable", executable, "--dry-run", "npm", "install", "react"]
    args, _ = _parse_command_line(argv)
    assert args.command == argv[4:]
    assert args.dry_run
    assert args.executable == executable


def test_cli_package_manager_dry_run_pip():
    """
    Test that a pip `--dry-run` flag is parsed correctly as such.
    """
    argv = ["scfw", "pip", "--dry-run", "install", "requests"]
    args, _ = _parse_command_line(argv)
    assert args.command == argv[1:]
    assert not args.dry_run
    assert not args.executable


def test_cli_package_manager_dry_run_npm():
    """
    Test that an npm `--dry-run` flag is parsed correctly as such.
    """
    argv = ["scfw", "npm", "--dry-run", "install", "react"]
    args, _ = _parse_command_line(argv)
    assert args.command == argv[1:]
    assert not args.dry_run
    assert not args.executable


def test_cli_pip_over_npm():
    """
    Test that a pip command is parsed correctly in the presence of an "npm" literal.
    """
    argv = ["scfw", "pip", "install", "npm"]
    args, _ = _parse_command_line(argv)
    assert args.command == argv[1:]


def test_cli_npm_over_pip():
    """
    Test that an npm command is parsed correctly in the presence of a "pip" literal.
    """
    argv = ["scfw", "npm", "install", "pip"]
    args, _ = _parse_command_line(argv)
    assert args.command == argv[1:]
