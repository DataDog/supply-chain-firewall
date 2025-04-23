"""
Tests of `PoetryCommand`.
"""

import pytest
import requests

from scfw.commands.poetry_command import PoetryCommand
from scfw.ecosystem import ECOSYSTEM

from .test_poetry import init_poetry_state, poetry_show, test_poetry_project

# We use Tree-sitter to test installation target resolution because it has no dependencies
TEST_TARGET = "tree-sitter"


@pytest.fixture
def test_target_latest():
    """
    Get the latest version of `TEST_TARGET` for use in testing.
    """
    r = requests.get(f"https://pypi.org/pypi/{TEST_TARGET}/json")
    r.raise_for_status()
    return r.json()["info"]["version"]


@pytest.mark.parametrize(
        "target_spec, target_version",
        [
            ["{}", None],
            ["{}@{}", "latest"],
            ["{}=={}", "0.24.0"],
            ["git+https://github.com/{}/py-tree-sitter", None],
            ["git+https://github.com/{}/py-tree-sitter#v{}", "0.24.0"],
            ["git+https://github.com/{}/py-tree-sitter.git", None],
            ["git+https://github.com/{}/py-tree-sitter.git#v{}", "0.24.0"],
            ["git+ssh://git@github.com/{}/py-tree-sitter", None],
            ["git+ssh://git@github.com/{}/py-tree-sitter#v{}", "0.24.0"],
            ["git+ssh://git@github.com/{}/py-tree-sitter.git", None],
            ["git+ssh://git@github.com/{}/py-tree-sitter.git#v{}", "0.24.0"],
            ["git+ssh://git@github.com:{}/py-tree-sitter", None],
            ["git+ssh://git@github.com:{}/py-tree-sitter#v{}", "0.24.0"],
            ["git+ssh://git@github.com:{}/py-tree-sitter.git", None],
            ["git+ssh://git@github.com:{}/py-tree-sitter.git#v{}", "0.24.0"],
        ]
)
def test_poetry_command_would_install(
    test_poetry_project,
    init_poetry_state,
    test_target_latest,
    target_spec,
    target_version
):
    """
    Tests that `PoetryCommand` correctly resolves installation targets for a variety
    of target specfications.
    """
    if not target_version:
        target = target_spec.format(TEST_TARGET)
    else:
        target = target_spec.format(TEST_TARGET, target_version)

    if not target_version or target_version == "latest":
        target_version = test_target_latest

    command = PoetryCommand(["poetry", "add", "--directory", test_poetry_project, target])
    targets = command.would_install()

    assert (
        len(targets) == 1
        and targets[0].ecosystem == ECOSYSTEM.PyPI
        and targets[0].package == TEST_TARGET
        and targets[0].version == target_version
    )
    assert poetry_show(test_poetry_project) == init_poetry_state
