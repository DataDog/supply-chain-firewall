import itertools
import multiprocessing as mp
import subprocess
import sys

from scfw.cli import parse_command_line
from scfw.commands import get_package_manager_command
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier
from scfw.verifiers import get_install_target_verifiers


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


def run_firewall() -> int:
    try:
        firewall_args, command = parse_command_line()
        # TODO: Print usage message and exit in this case
        if not command:
            return 0
        ecosystem, command = command

        command = get_package_manager_command(ecosystem, command)
        verifiers = get_install_target_verifiers()

        findings = verify_install_targets(verifiers, command.would_install())
        if findings:
            # TODO: Structure this output better
            for target, target_findings in findings.items():
                print(f"Installation target {target.show()}:")
                for finding in target_findings:
                    print(f"  - {finding}")
            print("\nThe installation request was blocked. No changes have been made.")
        else:
            if firewall_args.dry_run:
                print("Exiting without installing, no issues found for installation targets.")
            else:
                command.run()

        return 0
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
