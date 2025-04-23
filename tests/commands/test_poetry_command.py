"""
Tests of `PoetryCommand`.
"""

import pytest
import requests

from scfw.commands.poetry_command import PoetryCommand
from scfw.ecosystem import ECOSYSTEM

from .test_poetry import init_poetry_state, poetry_show, test_poetry_project


@pytest.fixture
def test_target_latest():
    """
    Get the latest version of Tree-sitter for use in testing.

    We use Tree-sitter to test installation target resolution because it has no dependencies.
    """
    r = requests.get(f"https://pypi.org/pypi/tree-sitter/json", timeout=5)
    r.raise_for_status()
    return r.json()["info"]["version"]


@pytest.fixture
def test_target_latest_download_url(test_target_latest):
    """
    Get the release tarball download link for the latest version of Tree-sitter.
    """
    return f"https://github.com/tree-sitter/py-tree-sitter/archive/refs/tags/v{test_target_latest}.tar.gz"


@pytest.mark.parametrize(
        "target_spec, target_version",
        [
            ["tree-sitter", "test_target_latest"],
            [f"tree-sitter@latest", "test_target_latest"],
            [f"tree-sitter==0.21.1", "0.21.1"],
            ["git+https://github.com/tree-sitter/py-tree-sitter", "test_target_latest"],
            ["git+https://github.com/tree-sitter/py-tree-sitter#v0.21.1", "0.21.1"],
            ["git+https://github.com/tree-sitter/py-tree-sitter.git", "test_target_latest"],
            ["git+https://github.com/tree-sitter/py-tree-sitter.git#v0.21.1", "0.21.1"],
            ["test_target_latest_download_url", "test_target_latest"],
            ["https://github.com/tree-sitter/py-tree-sitter/archive/refs/tags/v0.21.1.tar.gz", "0.21.1"],
        ]
)
def test_poetry_command_would_install(
    test_poetry_project,
    init_poetry_state,
    test_target_latest,
    test_target_latest_download_url,
    target_spec,
    target_version
):
    """
    Tests that `PoetryCommand` correctly resolves installation targets for a variety
    of target specfications.
    """
    if target_spec == "test_target_latest_download_url":
        target_spec = test_target_latest_download_url
    if target_version == "test_target_latest":
        target_version = test_target_latest

    command = PoetryCommand(["poetry", "add", "--directory", test_poetry_project, target_spec])
    targets = command.would_install()

    assert (
        len(targets) == 1
        and targets[0].ecosystem == ECOSYSTEM.PyPI
        and targets[0].package == "tree-sitter"
        and targets[0].version == target_version
    )
    assert poetry_show(test_poetry_project) == init_poetry_state
