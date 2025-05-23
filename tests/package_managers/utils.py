"""
Common utilities for package manager command tests.
"""

import os

from scfw.ecosystem import ECOSYSTEM


def read_top_packages(ecosystem: ECOSYSTEM) -> set[str]:
    """
    Read the top packages file for the given `ecosystem`.
    """
    test_dir = os.path.dirname(os.path.realpath(__file__, strict=True))
    top_packages_file = os.path.join(test_dir, f"top_{str(ecosystem).lower()}_packages.txt")
    with open(top_packages_file) as f:
        return set(f.read().split())


def select_test_install_target(top_packages: set[str], installed_packages: str) -> str:
    """
    Select a test target from `top_packages` that is not in the given installed
    packages output.

    This allows us to be certain when testing that nothing was installed in a
    dry-run.
    """
    try:
        while (choice := top_packages.pop()) in installed_packages:
            pass
        return choice
    except KeyError:
        raise RuntimeError("Unable to select a target package for testing")
