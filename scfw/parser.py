"""
A drop-in replacement for `argparse.ArgumentParser`.
"""

import argparse


class ArgumentError(Exception):
    """
    An exception for `ArgumentParser` to raise.
    """
    pass


class ArgumentParser(argparse.ArgumentParser):
    """
    A drop-in replacement for `argparse.ArgumentParser` with a patched
    implementation of the latter's `exit_on_error` behavior.

    See https://github.com/python/cpython/issues/103498 for more info.
    """
    def error(self, message):
        """
        Handle a parsing error.

        Args:
            message: Error message containing details about the error.
        """
        raise ArgumentError(message)
