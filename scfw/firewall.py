import itertools
import multiprocessing as mp
import subprocess
import sys

from scfw.cli import parse_command_line
from scfw.resolvers import get_install_targets_resolver
from scfw.target import InstallTarget
from scfw.verifier import InstallTargetVerifier
from scfw.verifiers import get_install_target_verifiers


def _perform_verify_task(target: InstallTarget, verifier: InstallTargetVerifier, findings: dict[InstallTarget, list[str]]):
    if (finding := verifier.verify(target)):
        if target not in findings:
            findings[target] = [finding]
        else:
            # https://bugs.python.org/issue36119
            # The manager does not monitor the lists for changes, so appending in place does nothing
            # Must replace the list after updating in order for the manager to register the change
            findings[target] += [finding]


def verify_install_targets(targets: list[InstallTarget], verifiers: list[InstallTargetVerifier]) -> dict[InstallTarget, list[str]]:
    manager = mp.Manager()
    findings = manager.dict()

    verify_tasks = itertools.product(targets, verifiers)

    with mp.Pool() as pool:
        pool.starmap(
            _perform_verify_task,
            [(target, verifier, findings) for target, verifier in verify_tasks]
        )

    return dict(findings)


def run_firewall() -> int:
    try:
        firewall_args, install_command = parse_command_line()
        # TODO: Print usage message and exit in this case
        if not install_command:
            return 0
        ecosystem, install_command = install_command

        resolver = get_install_targets_resolver(ecosystem)
        targets = resolver.resolve_targets(install_command)
        verifiers = get_install_target_verifiers()

        findings = verify_install_targets(targets, verifiers)
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
                subprocess.run(install_command)

        return 0
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
