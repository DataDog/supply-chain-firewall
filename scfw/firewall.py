import itertools
import multiprocessing as mp
import sys
import logging

from scfw.cli import parse_command_line
from scfw.commands import get_package_manager_command
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier
from scfw.verifiers import get_install_target_verifiers
from scfw.config import LOG_DD

log = logging.getLogger()


def _perform_verify_task(verifier: InstallTargetVerifier, target: InstallTarget, findings: dict[InstallTarget, list[str]]):
    if (finding := verifier.verify(target)):
        if target not in findings:
            findings[target] = [finding]
        else:
            # https://bugs.python.org/issue36119
            # The manager does not monitor the lists for changes, so appending in place does nothing
            # Must replace the list after updating in order for the manager to register the change
            findings[target] += [finding]


def verify_install_targets(verifiers: list[InstallTargetVerifier], targets: list[InstallTarget]) -> dict[InstallTarget, list[str]]:
    manager = mp.Manager()
    findings = manager.dict()

    verify_tasks = itertools.product(verifiers, targets)

    with mp.Pool() as pool:
        pool.starmap(
        _perform_verify_task,
        [(verifier, target, findings) for verifier, target in verify_tasks]
    )

    return dict(findings)


def print_findings(findings: dict[InstallTarget, list[str]]):
    # TODO: Format this output in a more robust way
    for target, target_findings in findings.items():
        print(f"Installation target {target.show()}:")
        for finding in target_findings:
            print(f"  - {finding}")


def run_firewall() -> int:
    try:

        ddlog = logging.getLogger(LOG_DD)
        cli_args, cli_command = parse_command_line()
        # TODO: Print usage message and exit in this case
        if not cli_command:
            return 0
        ecosystem, command = cli_command

        pkgmgr_command = get_package_manager_command(ecosystem, command, executable=cli_args.executable)
        if targets := pkgmgr_command.would_install():

            verifiers = get_install_target_verifiers()

            if (findings := verify_install_targets(verifiers, targets)):
                print_findings(findings)
                tags = map(lambda x: f"{x.package}@{x.version}", findings.keys())
                ddlog.info(f"Instalation was block while attempting to run {command}", extra={"tags":[tags]})
                print("\nThe installation request was blocked. No changes have been made.")
                return 0

            if cli_args.dry_run:
                print("Exiting without installing, no issues found for installation targets.")
                return 0

        # tags = map(lambda x: f"{x.package}@{x.version}", [InstallTarget("pip", "requests", "2.26.0")])
        tags = map(lambda x: f"{x.package}@{x.version}", targets)
        ddlog.info(f"Running {command}", extra={"tags":tags})
        pkgmgr_command.run()
        return 0

    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
