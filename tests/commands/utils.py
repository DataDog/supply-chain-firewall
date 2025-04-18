import os
import subprocess
import sys
from typing import Optional


def read_top_packages(file: str) -> set[str]:
    """
    Read the top packages from the given file, assumed to be in the same
    directory as this source file.
    """
    test_dir = os.path.dirname(os.path.realpath(__file__, strict=True))
    filepath = os.path.join(test_dir, file)
    with open(filepath) as f:
        return set(f.read().split())


def list_installed_packages(package_manager: str) -> str:
    """
    Get the current state of installed packages for the given package manager.
    """
    match package_manager:
        case "npm":
            command = ["npm", "list", "--all"]
        case "pip":
            command = [sys.executable, "-m", "pip", "list", "--format", "freeze"]
        case _:
            raise ValueError(f"Unsupported package manager '{package_manager}'")

    p = subprocess.run(command, check=True, text=True, capture_output=True)
    return p.stdout.lower()


def select_test_install_target(top_packages: set[str], installed_packages: str) -> Optional[str]:
    """
    Select a test target from `top_packages` that is not in the given installed
    packages output.  If there is no such package, return `None`.

    This allows us to be certain when testing that nothing was installed in a
    dry-run.
    """
    try:
        while (choice := top_packages.pop()) in installed_packages:
            pass
    except KeyError:
        choice = None

    return choice
