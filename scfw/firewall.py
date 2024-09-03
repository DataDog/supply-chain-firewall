"""
Provides the core orchestration layer for the supply-chain firewall, including
its main routine, `run_firewall()`.
"""

import concurrent.futures as cf
import itertools
import logging
import time

import scfw.cli as cli
import scfw.commands as commands
from scfw.dd_logger import DD_LOG_NAME
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier
import scfw.verifiers as verifs

# Firewall root logger configured to write to stderr
_log = logging.getLogger()
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
_log.addHandler(_handler)


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
    findings = {}

    with cf.ThreadPoolExecutor() as executor:
        task_results = {
            executor.submit(lambda v, t: v.verify(t), verifier, target): (verifier.name(), target)
            for verifier, target in itertools.product(verifiers, targets)
        }
        for future in cf.as_completed(task_results):
            verifier, target = task_results[future]
            if (finding := future.result()):
                _log.info(f"{verifier} had findings for target {target.show()}")
                if target not in findings:
                    findings[target] = [finding]
                else:
                    findings[target].append(finding)
            else:
                _log.info(f"{verifier} had no findings for target {target.show()}")

    _log.info(
        f"Verification complete: {len(findings)} of {len(targets)} installation targets had findings"
    )
    return findings


def print_findings(findings: dict[InstallTarget, list[str]]):
    """
    Print the findings accrued for targets during verification.

    Args:
        findings:
            The `dict` of findings for the verified installation targets returned
            by `verify_install_targets()`.
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
        args, help = cli.parse_command_line()
        if not args.command:
            print(help)
            return 0

        _log.setLevel(args.log_level)
        dd_log = logging.getLogger(DD_LOG_NAME)

        _log.info(f"Starting supply-chain firewall on {time.asctime(time.localtime())}")
        _log.info(f"Command: '{' '.join(args.command)}'")
        _log.debug(f"Command line: {vars(args)}")

        command = commands.get_package_manager_command(args.command, executable=args.executable)
        targets = command.would_install()
        _log.info(f"Command would install: [{', '.join(t.show() for t in targets)}]")

        if targets:
            verifiers = verifs.get_install_target_verifiers()
            _log.info(
                f"Using installation target verifiers: [{', '.join(v.name() for v in verifiers)}]"
            )

            if (findings := verify_install_targets(verifiers, targets)):
                dd_log.info(
                    f"Installation was blocked while attempting to run '{' '.join(args.command)}'",
                    extra={"targets": map(lambda x: x.show(), findings)}
                )
                print_findings(findings)
                print("\nThe installation request was blocked. No changes have been made.")
                return 0

            if args.dry_run:
                _log.info("Firewall dry-run mode enabled: no packages will be installed")
                print("Exiting without installing, no issues found for installation targets.")
                return 0

        dd_log.info(
            f"Running '{' '.join(args.command)}'",
            extra={"targets": map(lambda x: x.show(), targets)}
        )
        command.run()
        return 0

    except Exception as e:
        _log.error(e)
        return 1
