import sys

from scfw.commands.pip_command import PipCommand

from .test_pip import INIT_PIP_STATE, TEST_TARGET, pip_list


def test_pip_command_would_install_basic_usage():
    """
    Test that `PipCommand.would_install` does not modify the pip state in the
    basic use case of a "live" install command.
    """
    command_line = ["pip", "install", TEST_TARGET]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert targets
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_command_would_install_help_pip_short():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the
    pip state when the short form help option is present and attached to the `pip`
    portion of the command.
    """
    command_line = ["pip", "-h", "install", TEST_TARGET]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert not targets
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_command_would_install_help_pip_long():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the
    pip state when the long form help option is present and attached to the `pip`
    portion of the command.
    """
    command_line = ["pip", "--help", "install", TEST_TARGET]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert not targets
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_command_would_install_help_pip_install_short():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the
    pip state when the short form help option is present and attached to the `pip`
    portion of the command.
    """
    command_line = ["pip", "install", "-h", TEST_TARGET]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert not targets
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_command_would_install_help_pip_install_long():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the
    pip state when the long form help option is present and attached to the `pip`
    portion of the command.
    """
    command_line = ["pip", "install", "--help", TEST_TARGET]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert not targets
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_command_would_install_dry_run_correct():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the pip
    state when the dry-run option is already present and used correctly in the command.
    """
    command_line = ["pip", "install" "--dry-run", TEST_TARGET]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert not targets
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_command_would_install_dry_run_incorrect():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the pip
    state when the dry-run options is already present but used incorrectly in the
    command.
    """
    command_line = ["pip", "--dry-run", "install", TEST_TARGET]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert not targets
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_command_would_install_report():
    """
    Test that `PipCommand.would_install` is able to override any `--report` options
    already present in the pip command line (i.e., to obtain the report on stdout).
    """
    command_line = ["pip", "install", "--report", "report.json", TEST_TARGET]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert targets
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_command_would_install_error():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the pip
    state when the given command encounters an error.
    """
    command_line = ["pip", "install", "--non-existent-option", TEST_TARGET]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert not targets
    assert pip_list(sys.executable) == INIT_PIP_STATE
