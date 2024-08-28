import concurrent.futures as cf
import itertools
import logging

from scfw.cli import parse_command_line
from scfw.commands import get_package_manager_command
from scfw.dd_logger import DD_LOG_NAME
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier
from scfw.verifiers import get_install_target_verifiers

# Firewall root logger configured to write to stderr
log = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
log.addHandler(handler)

# Datadog logger
dd_log = logging.getLogger(DD_LOG_NAME)


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

    # Verify every target against every verifier
    verify_tasks = itertools.product(verifiers, targets)

    with cf.ThreadPoolExecutor() as executor:
        task_results = {
            executor.submit(lambda v, t: v.verify(t), verifier, target): target
            for verifier, target in verify_tasks
        }
        for future in cf.as_completed(task_results):
            target = task_results[future]
            if (finding := future.result()):
                if target not in findings:
                    findings[target] = [finding]
                else:
                    findings[target].append(finding)

    return findings


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
        args, help = parse_command_line()
        if not args.command:
            print(help)
            return 0

        log.setLevel(args.log_level)

        command = get_package_manager_command(args.command, executable=args.executable)
        if (targets := command.would_install()):

            verifiers = get_install_target_verifiers()

            if (findings := verify_install_targets(verifiers, targets)):
                dd_log.info(
                    f"Installation was blocked while attempting to run {args.command}",
                    extra={"targets": map(lambda x: x.show(), findings)}
                )
                print_findings(findings)
                print("\nThe installation request was blocked. No changes have been made.")
                return 0

            if args.dry_run:
                print("Exiting without installing, no issues found for installation targets.")
                return 0

        dd_log.info(f"Running {args.command}", extra={"targets": map(lambda x: x.show(), targets)})
        command.run()
        return 0

    except Exception as e:
        log.error(e)
        return 1
