from scfw.commands.npm_command import NpmCommand
from scfw.ecosystem import ECOSYSTEM

from .test_npm import INIT_NPM_STATE, TEST_TARGET, npm_list


def _test_npm_command_would_install(command_line: list[str], has_targets: bool):
    """
    Backend function for testing that an `NpmCommand.would_install` call either
    does or does not have install targets and does not modify the local npm
    installation state.
    """
    command = NpmCommand(command_line)
    targets = command.would_install()
    if has_targets:
        assert targets
    else:
        assert not targets
    assert npm_list() == INIT_NPM_STATE


def test_npm_command_would_install_basic_usage():
    """
    Test that `NpmCommand.would_install` does not modify the npm state in the
    basic use case of a "live" install command.
    """
    _test_npm_command_would_install(["npm", "install", TEST_TARGET], has_targets=True)


def test_npm_command_would_install_help_npm_short():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the
    npm state when the short form help option is present and attached to the `npm`
    portion of the command.
    """
    _test_npm_command_would_install(["npm", "-h", "install", TEST_TARGET], has_targets=False)


def test_npm_command_would_install_help_npm_long():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the
    npm state when the long form help option is present and attached to the `npm`
    portion of the command.
    """
    _test_npm_command_would_install(["npm", "--help", "install", TEST_TARGET], has_targets=False)


def test_npm_command_would_install_help_npm_install_short():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the
    npm state when the short form help option is present and attached to the `npm`
    portion of the command.
    """
    _test_npm_command_would_install(["npm", "install", "-h", TEST_TARGET], has_targets=False)


def test_npm_command_would_install_help_npm_install_long():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the
    npm state when the long form help option is present and attached to the `npm`
    portion of the command.
    """
    _test_npm_command_would_install(["npm", "install", "--help", TEST_TARGET], has_targets=False)


def test_npm_command_would_install_dry_run_npm():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the npm
    state when the dry-run option is already present and attached to the `npm`
    portion of the command.
    """
    _test_npm_command_would_install(["npm", "--dry-run", "install", TEST_TARGET], has_targets=False)


def test_npm_command_would_install_dry_run_npm_install():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the npm
    state when the dry-run option is already present and attached to the `npm install`
    portion of the command.
    """
    _test_npm_command_would_install(["npm", "install", "--dry-run", TEST_TARGET], has_targets=False)


def test_npm_command_would_install_error():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the npm
    state when the given command encounters an error.
    """
    _test_npm_command_would_install(["npm", "--non-existent-option"], has_targets=False)
