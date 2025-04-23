"""
Tests of `PoetryCommand`.
"""

import pytest

from scfw.commands.poetry_command import PoetryCommand
from scfw.ecosystem import ECOSYSTEM

from .test_poetry import TARGET, init_poetry_state, new_poetry_project, poetry_show, target_latest, target_releases

TARGET_REPO = f"https://github.com/{TARGET}/py-tree-sitter"


@pytest.fixture
def target_latest_download_url(target_latest):
    """
    Get the release tarball download link for the latest version of `TARGET`.
    """
    return f"{TARGET_REPO}/archive/refs/tags/v{target_latest}.tar.gz"


@pytest.mark.parametrize(
        "target_spec, target_version",
        [
            [TARGET, "target_latest"],
            [f"{TARGET}@latest", "target_latest"],
            [f"{TARGET}==0.21.1", "0.21.1"],
            [f"git+{TARGET_REPO}", "target_latest"],
            [f"git+{TARGET_REPO}#v0.21.1", "0.21.1"],
            [f"git+{TARGET_REPO}.git", "target_latest"],
            [f"git+{TARGET_REPO}.git#v0.21.1", "0.21.1"],
            ["target_latest_download_url", "target_latest"],
            [f"{TARGET_REPO}/archive/refs/tags/v0.21.1.tar.gz", "0.21.1"],
        ]
)
def test_poetry_command_would_install(
    new_poetry_project,
    init_poetry_state,
    target_latest,
    target_latest_download_url,
    target_spec,
    target_version
):
    """
    Tests that `PoetryCommand` correctly resolves installation targets for a variety
    of target specfications.
    """
    if target_spec == "target_latest_download_url":
        target_spec = target_latest_download_url
    if target_version == "target_latest":
        target_version = target_latest

    command = PoetryCommand(["poetry", "add", "--directory", new_poetry_project, target_spec])
    targets = command.would_install()

    assert (
        len(targets) == 1
        and targets[0].ecosystem == ECOSYSTEM.PyPI
        and targets[0].package == "tree-sitter"
        and targets[0].version == target_version
    )
    assert poetry_show(new_poetry_project) == init_poetry_state
