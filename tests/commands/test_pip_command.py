import sys

from scfw.commands.pip_command import PipCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget

from .test_pip import INIT_PIP_STATE, TEST_TARGET, pip_list


def _test_pip_command_would_install(command_line: list[str], has_targets: bool):
    """
    Backend function for testing that a `PipCommand.would_install` call either
    does or does not have install targets and does not modify the local pip
    installation state.
    """
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    if has_targets:
        assert targets
    else:
        assert not targets
    assert pip_list() == INIT_PIP_STATE


def test_pip_command_would_install_basic_usage():
    """
    Test that `PipCommand.would_install` does not modify the pip state in the
    basic use case of a "live" install command.
    """
    _test_pip_command_would_install(["pip", "install", TEST_TARGET], has_targets=True)


def test_pip_command_would_install_help_pip_short():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the
    pip state when the short form help option is present and attached to the `pip`
    portion of the command.
    """
    _test_pip_command_would_install(["pip", "-h", "install", TEST_TARGET], has_targets=False)


def test_pip_command_would_install_help_pip_long():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the
    pip state when the long form help option is present and attached to the `pip`
    portion of the command.
    """
    _test_pip_command_would_install(["pip", "--help", "install", TEST_TARGET], has_targets=False)


def test_pip_command_would_install_help_pip_install_short():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the
    pip state when the short form help option is present and attached to the `pip`
    portion of the command.
    """
    _test_pip_command_would_install(["pip", "install", "-h", TEST_TARGET], has_targets=False)


def test_pip_command_would_install_help_pip_install_long():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the
    pip state when the long form help option is present and attached to the `pip`
    portion of the command.
    """
    _test_pip_command_would_install(["pip", "install", "--help", TEST_TARGET], has_targets=False)


def test_pip_command_would_install_dry_run_correct():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the pip
    state when the dry-run option is already present and used correctly in the command.
    """
    _test_pip_command_would_install(["pip", "install" "--dry-run", TEST_TARGET], has_targets=False)


def test_pip_command_would_install_dry_run_incorrect():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the pip
    state when the dry-run options is already present but used incorrectly in the
    command.
    """
    _test_pip_command_would_install(["pip", "--dry-run", "install", TEST_TARGET], has_targets=False)


def test_pip_command_would_install_report():
    """
    Test that `PipCommand.would_install` is able to override any `--report` options
    already present in the pip command line (i.e., to obtain the report on stdout).
    """
    _test_pip_command_would_install(["pip", "install", "--report", "report.json", TEST_TARGET], has_targets=True)


def test_pip_command_would_install_error():
    """
    Test that `PipCommand.would_install` returns nothing and does not modify the pip
    state when the given command encounters an error.
    """
    _test_pip_command_would_install(["pip", "install", "--non-existent-option", TEST_TARGET], has_targets=False)


def test_pip_command_would_install_exact():
    """
    Test that `PipCommand.would_install` gives the right answer relative to an
    exact top-level installation target and its dependencies.
    """
    true_targets = list(
        map(
            lambda p: InstallTarget(ECOSYSTEM.PIP, p[0], p[1]),
            [
                ("certifi", "2024.7.4"),
                ("charset-normalizer", "3.3.2"),
                ("idna", "3.8"),
                ("requests", "2.32.3"),
                ("urllib3", "2.2.2")
            ]
        )
    )

    command_line = ["pip", "install", "--ignore-installed", "requests==2.32.3"]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert len(targets) == len(true_targets)
    assert all(target in true_targets for target in targets)
