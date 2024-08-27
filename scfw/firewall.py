import itertools
import logging
import multiprocessing as mp
import sys

from scfw.cli import parse_command_line
from scfw.commands import get_package_manager_command
from scfw.config import LOG_DD
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier
from scfw.verifiers import get_install_target_verifiers

log = logging.getLogger()


def _perform_verify_task(
    verifier: InstallTargetVerifier,
    target: InstallTarget,
    findings: dict[InstallTarget, list[str]]
):
    """
    Execute a single verification task (i.e., for a single verifier-target pair)
    and collect the results.

    Args:
        verifier: The `InstallTargetVerifier` to use in the task.
        target: The `InstallTarget` to be verified
        findings: A `dict` for accumulating verification findings across tasks
    """
    if (finding := verifier.verify(target)):
        if target not in findings:
            findings[target] = [finding]
        else:
            # https://bugs.python.org/issue36119
            # The manager does not monitor the lists for changes, so appending in place does nothing
            # Must replace the list after updating in order for the manager to register the change
            findings[target] += [finding]


def verify_install_targets(
    verifiers: list[InstallTargetVerifier],
    targets: list[InstallTarget]
) -> dict[InstallTarget, list[str]]:
    """
    Verify a set of installation targets against a set of verifiers.

    Args:
        verifiers: The set of verifiers to use against the installation targets.
        targers: A list of installation targets to be verified.

    Returns:
        A `dict` associating installation targets with its verification findings.

        If a given target is not present as a key in the returned `dict`, there
        were no findings for it. An empty returned `dict` indicates that no target
        had findings, i.e., that the installation can proceed.
    """
    manager = mp.Manager()
    findings = manager.dict()

    verify_tasks = itertools.product(verifiers, targets)

    with mp.Pool() as pool:
        pool.starmap(
            _perform_verify_task,
            [(verifier, target, findings) for verifier, target in verify_tasks],
        )

    return dict(findings)


def print_findings(findings: dict[InstallTarget, list[str]]):
    """
    Print the findings accrued for targets during verification.

    Args:
        findings: The `dict` of findings for the verified installation targets.
    """
    for target, target_findings in findings.items():
        print(f"Installation target {target.show()}:")
        for finding in target_findings:
            print(f"  - {finding}")


def run_firewall() -> int:
    """
    The main routine for the supply-chain firewall.

    Returns:
        An integer exit code (0 or 1).
    """
    try:

        ddlog = logging.getLogger(LOG_DD)

        args, help = parse_command_line()
        if not args.command:
            print(help)
            return 0

        command = get_package_manager_command(args.command, executable=args.executable)
        if targets := command.would_install():

            verifiers = get_install_target_verifiers()

            if (findings := verify_install_targets(verifiers, targets)):
                tags = map(lambda x: x.show(), findings)
                ddlog.info(f"Installation was blocked while attempting to run {command}", extra={"tags": [tags]})
                print_findings(findings)
                print("\nThe installation request was blocked. No changes have been made.")
                return 0

            if args.dry_run:
                print("Exiting without installing, no issues found for installation targets.")
                return 0

        tags = map(lambda x: x.show(), targets)
        ddlog.info(f"Running {args.command}", extra={"tags": tags})
        command.run()
        return 0

    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
