from scfw.commands.npm_command import NpmCommand

from .test_npm import INIT_NPM_STATE, TEST_TARGET, npm_list


def test_npm_command_would_install_basic_usage():
    """
    Test that `NpmCommand.would_install` does not modify the npm state in the
    basic use case of a "live" install command.
    """
    command_line = ["npm", "install", TEST_TARGET]
    command = NpmCommand(command_line)
    targets = command.would_install()
    assert targets
    assert npm_list() == INIT_NPM_STATE


def test_npm_command_would_install_help_npm_short():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the
    npm state when the short form help option is present and attached to the `npm`
    portion of the command.
    """
    command_line = ["npm", "-h", "install", TEST_TARGET]
    command = NpmCommand(command_line)
    targets = command.would_install()
    assert not targets
    assert npm_list() == INIT_NPM_STATE


def test_npm_command_would_install_help_npm_long():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the
    npm state when the long form help option is present and attached to the `npm`
    portion of the command.
    """
    command_line = ["npm", "--help", "install", TEST_TARGET]
    command = NpmCommand(command_line)
    targets = command.would_install()
    assert not targets
    assert npm_list() == INIT_NPM_STATE


def test_npm_command_would_install_help_npm_install_short():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the
    npm state when the short form help option is present and attached to the `npm`
    portion of the command.
    """
    command_line = ["npm", "install", "-h", TEST_TARGET]
    command = NpmCommand(command_line)
    targets = command.would_install()
    assert not targets
    assert npm_list() == INIT_NPM_STATE


def test_npm_command_would_install_help_npm_install_long():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the
    npm state when the long form help option is present and attached to the `npm`
    portion of the command.
    """
    command_line = ["npm", "install", "--help", TEST_TARGET]
    command = NpmCommand(command_line)
    targets = command.would_install()
    assert not targets
    assert npm_list() == INIT_NPM_STATE


def test_npm_command_would_install_dry_run_npm():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the npm
    state when the dry-run option is already present and attached to the `npm`
    portion of the command.
    """
    command_line = ["npm", "--dry-run", "install", TEST_TARGET]
    command = NpmCommand(command_line)
    targets = command.would_install()
    assert not targets
    assert npm_list() == INIT_NPM_STATE


def test_npm_command_would_install_dry_run_npm_install():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the npm
    state when the dry-run option is already present and attached to the `npm install`
    portion of the command.
    """
    command_line = ["npm", "install", "--dry-run", TEST_TARGET]
    command = NpmCommand(command_line)
    targets = command.would_install()
    assert not targets
    assert npm_list() == INIT_NPM_STATE


def test_npm_command_would_install_error():
    """
    Test that `NpmCommand.would_install` returns nothing and does not modify the npm
    state when the given command encounters an error.
    """
    command_line = ["npm", "--non-existent-option"]
    command = NpmCommand(command_line)
    targets = command.would_install()
    assert not targets
    assert npm_list() == INIT_NPM_STATE
