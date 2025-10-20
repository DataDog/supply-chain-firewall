"""
Provides a class for spinning up ephemeral Go environments to run commands in.
"""

import os
from pathlib import Path
import platform
import shutil
import subprocess
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Optional, Type, TypeVar

_TempGoEnvironmentType = TypeVar('_TempGoEnvironmentType', bound='TempGoEnvironment')


class TempGoEnvironment(TemporaryDirectory):
    """
    Prepares a temporary environment in which go commands may be executed without affecting
    the user's global environment.

    This may be used as a context manager. On completion of the context the temporary
    environment will be removed from the filesystem, alongside any changes that may have
    been made to the current project.

    Alternatively, when done with the environment, you may call cleanup() to remove the
    temporary environment.
    """
    def __init__(self, executable: str):
        """
        Initialize a new `TempGoEnvironment`.

        Args:
            executable: A `str` path in the local filesystem to the `go` executable to use.
        """
        TemporaryDirectory.__init__(self)

        self._executable = executable
        self._restore_mod_file = False
        self._restore_sum_file = False
        self._remove_sum_file = False
        self._original_dir = None

        gomod_command = [self._executable, "env", "GOMOD"]
        gomod = subprocess.run(gomod_command, check=True, text=True, capture_output=True)
        gomod_path = gomod.stdout.strip()
        if gomod_path != "/dev/null" and gomod_path != "NUL":
            self._original_dir = Path(gomod_path).absolute().parent

        self._create_tmp_env()

    def __enter__(self: _TempGoEnvironmentType) -> _TempGoEnvironmentType:
        """
        Convert the `TempGoEnvironment` to a context manager.

        Returns:
            The object itself managing the temporary environment.
        """
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ):
        """
        Clear the temporary environment and undo any changes made to the current project.
        """
        self.cleanup()

    def cleanup(self):
        """
        Clear the temporary environment and undo any changes made to the current project.
        """
        if self._original_dir is not None:
            if self._restore_mod_file:
                mod_file = self._original_dir / "go.mod"
                tmp_file = self.tmp_dir / "go.mod"
                shutil.copy(tmp_file, mod_file)

            sum_file = self._original_dir / "go.sum"
            if self._restore_sum_file:
                tmp_file = self.tmp_dir / "go.sum"
                shutil.copy(tmp_file, sum_file)
            elif self._remove_sum_file:
                os.remove(sum_file)

        TemporaryDirectory.cleanup(self)

    def run(self, args: list[str], local: bool = False) -> subprocess.CompletedProcess:
        """
        Execute a go command within the temporary environment.

        Args:
            args: The list of arguments passed to `go`.

        Returns:
            A representation of the finished proccess.
        """
        return subprocess.run(
            [self._executable] + args,
            cwd=None if local else self._dry_run_dir,
            env=self.env,
            check=True,
            text=True,
            capture_output=True,
        )

    def duplicate_go_mod(self):
        """
        Duplicate the go.mod and go.sum in the nearest ancestor directory.

        On clean up, these files are recovered, in case they were modified.
        """
        if self._original_dir is None:
            raise GoModNotFoundError("Failed to find a 'go.mod' file to operate on")

        mod_file = self._original_dir / "go.mod"
        shutil.copy(mod_file, self.tmp_dir)
        self._restore_mod_file = True

        sum_file = self._original_dir / "go.sum"
        if sum_file.exists():
            shutil.copy(sum_file, self.tmp_dir)
            self._restore_sum_file = True
        else:
            self._remove_sum_file = True

    def _create_tmp_env(self):
        """
        Create the temporary environment and set every environment variable required to run
        `go` commands keeping the global environment clean.
        """
        self.tmp_dir = Path(self.name)

        go_dir = self.tmp_dir / "go"
        go_dir.mkdir(mode=0o750)

        self._dry_run_dir = self.tmp_dir / "dry_run"
        self._dry_run_dir.mkdir(mode=0o750)

        cache_dir = self.tmp_dir / "cache"
        cache_dir.mkdir(mode=0o750)

        mod_cache_dir = self.tmp_dir / "mod_cache"
        mod_cache_dir.mkdir(mode=0o750)

        # Go searches each directory listed in GOPATH to find source code,
        # but new packages are always downloaded into the first directory
        # in the list.
        gopath_command = [self._executable, "env", "GOPATH"]
        gopath = subprocess.run(gopath_command, check=True, text=True, capture_output=True)

        separator = ":"
        if platform.system() == "Windows":
            separator = ";"

        self.env = os.environ.copy()
        self.env['GOPATH'] = f"{go_dir}{separator}{gopath.stdout.strip()}"
        self.env['GOCACHE'] = str(cache_dir)
        self.env['GOMODCACHE'] = str(mod_cache_dir)


class GoModNotFoundError(Exception):
    """
    An exception that occurs when an attempt is made to execute a go command that must be
    executed within a go project (with a go.mod file), but not such file could be found
    in the direct directory hierarchy.
    """
    pass
