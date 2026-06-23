"""
Tests of `FindingsListVerifier`.
"""

import pytest
from typing import Optional

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import Finding, FindingSeverity, UnverifiablePackage
from scfw.verifiers.list_verifier import FindingsListVerifier, FindingsMap

from .. import utils

# Test findings list YAML
FINDINGS_LIST_1 = """\
findings:
  - severity: CRITICAL
    finding: "This is a critical finding in the first test findings list"
    packages:
      - ecosystem: PyPI
        name: pynamodb
      - ecosystem: npm
        name: react
        versions:
          - 18.3.0

  - severity: WARNING
    finding: "This is a warning finding in the first test findings list"
    packages:
      - ecosystem: PyPI
        name: numpy
"""

# The parsed findings map for `FINDINGS_LIST_1`
RAW_MAP_1 = {
    ECOSYSTEM.Npm: {
        "react": {
            "18.3.0": [
                (FindingSeverity.CRITICAL, "This is a critical finding in the first test findings list"),
            ],
        },
    },
    ECOSYSTEM.PyPI: {
        "numpy": {
            "*": [
                (FindingSeverity.WARNING, "This is a warning finding in the first test findings list"),
            ],
        },
        "pynamodb": {
            "*": [
                (FindingSeverity.CRITICAL, "This is a critical finding in the first test findings list"),
            ],
        },
    },
}

# Test findings list YAML
FINDINGS_LIST_2 = """\
findings:
  - severity: CRITICAL
    finding: "This is a critical finding in the second test findings list"
    packages:
      - ecosystem: npm
        name: react
        versions:
          - 18.2.0

  - severity: CRITICAL
    finding: "This is another critical finding in the second test findings list"
    packages:
      - ecosystem: PyPI
        name: numpy
        versions:
          - 2.3.5

  - severity: WARNING
    finding: "This is a warning finding in the second test findings list"
    packages:
      - ecosystem: PyPI
        name: numpy
        versions:
          - 2.3.5
"""

# The parsed findings map for `FINDINGS_LIST_2`
RAW_MAP_2 = {
    ECOSYSTEM.Npm: {
        "react": {
            "18.2.0": [
                (FindingSeverity.CRITICAL, "This is a critical finding in the second test findings list"),
            ],
        },
    },
    ECOSYSTEM.PyPI: {
        "numpy": {
            "2.3.5": [
                (FindingSeverity.CRITICAL, "This is another critical finding in the second test findings list"),
                (FindingSeverity.WARNING, "This is a warning finding in the second test findings list"),
            ],
        },
    },
}

# The parsed findings map for the merge of `FINDINGS_MAP_1` and `FINDINGS_MAP_2`
RAW_MAP_MERGED = {
    ECOSYSTEM.Npm: {
        "react": {
            "18.2.0": [
                (FindingSeverity.CRITICAL, "This is a critical finding in the second test findings list"),
            ],
            "18.3.0": [
                (FindingSeverity.CRITICAL, "This is a critical finding in the first test findings list"),
            ],
        },
    },
    ECOSYSTEM.PyPI: {
        "numpy": {
            "*": [
                (FindingSeverity.WARNING, "This is a warning finding in the first test findings list"),
            ],
            "2.3.5": [
                (FindingSeverity.CRITICAL, "This is another critical finding in the second test findings list"),
                (FindingSeverity.WARNING, "This is a warning finding in the second test findings list"),
            ],
        },
        "pynamodb": {
            "*": [
                (FindingSeverity.CRITICAL, "This is a critical finding in the first test findings list"),
            ],
        },
    },
}


@pytest.mark.parametrize(
    "findings_list, raw_map",
    [
        (FINDINGS_LIST_1, RAW_MAP_1),
        (FINDINGS_LIST_2, RAW_MAP_2),
    ]
)
def test_findings_map_from_yaml(
    findings_list: str,
    raw_map: dict[ECOSYSTEM, dict[str, dict[str, list[tuple[FindingSeverity, str]]]]],
):
    """
    Test that `FindingsMap.from_yaml()` parses correctly given well-formed input.
    """
    assert FindingsMap.from_yaml(findings_list)._raw_map == raw_map


def test_findings_map_merge():
    """
    Test that `FindingsMap.merge()` correctly merges findings maps.
    """
    findings_map_1 = FindingsMap.from_yaml(FINDINGS_LIST_1)
    findings_map_2 = FindingsMap.from_yaml(FINDINGS_LIST_2)

    findings_map_1.merge(findings_map_2)

    assert findings_map_1._raw_map == RAW_MAP_MERGED


@pytest.mark.parametrize(
    "package,unverifiable,findings",
    [
        (
            utils.build_registry_package(ECOSYSTEM.Npm, "react", "18.2.0"),
            False,
            [(FindingSeverity.CRITICAL, "This is a critical finding in the second test findings list")],
        ),
        (
            utils.build_registry_package(ECOSYSTEM.Npm, "react", "18.3.0"),
            False,
            [(FindingSeverity.CRITICAL, "This is a critical finding in the first test findings list")],
        ),
        (
            utils.build_registry_package(ECOSYSTEM.PyPI, "numpy", "foo"),
            False,
            [(FindingSeverity.WARNING, "This is a warning finding in the first test findings list")],
        ),
        (
            utils.build_registry_package(ECOSYSTEM.PyPI, "numpy", "2.3.5"),
            False,
            [
                (FindingSeverity.WARNING, "This is a warning finding in the first test findings list"),
                (FindingSeverity.CRITICAL, "This is another critical finding in the second test findings list"),
                (FindingSeverity.WARNING, "This is a warning finding in the second test findings list"),
            ],
        ),
        (
            utils.build_registry_package(ECOSYSTEM.PyPI, "pynamodb", "foo"),
            False,
            [(FindingSeverity.CRITICAL, "This is a critical finding in the first test findings list")],
        ),
        (
            Package(ECOSYSTEM.Npm, "react", "18.2.0"),
            False,
            [(FindingSeverity.CRITICAL, "This is a critical finding in the second test findings list")],
        ),
        (
            Package(ECOSYSTEM.Npm, "react", "18.3.0"),
            False,
            [(FindingSeverity.CRITICAL, "This is a critical finding in the first test findings list")],
        ),
        (
            Package(ECOSYSTEM.PyPI, "numpy", "foo"),
            False,
            [(FindingSeverity.WARNING, "This is a warning finding in the first test findings list")],
        ),
        (
            Package(ECOSYSTEM.PyPI, "numpy", "2.3.5"),
            False,
            [
                (FindingSeverity.WARNING, "This is a warning finding in the first test findings list"),
                (FindingSeverity.CRITICAL, "This is another critical finding in the second test findings list"),
                (FindingSeverity.WARNING, "This is a warning finding in the second test findings list"),
            ],
        ),
        (
            Package(ECOSYSTEM.PyPI, "pynamodb", "foo"),
            False,
            [(FindingSeverity.CRITICAL, "This is a critical finding in the first test findings list")],
        ),
        (utils.build_remote_non_registry_package(ECOSYSTEM.Npm, "react", "18.2.0"), True, None),
        (utils.build_remote_non_registry_package(ECOSYSTEM.Npm, "react", "18.3.0"), True, None),
        (utils.build_remote_non_registry_package(ECOSYSTEM.PyPI, "numpy", "foo"), True, None),
        (utils.build_remote_non_registry_package(ECOSYSTEM.PyPI, "numpy", "2.3.5"), True, None),
        (utils.build_remote_non_registry_package(ECOSYSTEM.PyPI, "pynamodb", "foo"), True, None),
        (utils.build_local_package(ECOSYSTEM.Npm, "react", "18.2.0"), True, None),
        (utils.build_local_package(ECOSYSTEM.Npm, "react", "18.3.0"), True, None),
        (utils.build_local_package(ECOSYSTEM.PyPI, "numpy", "foo"), True, None),
        (utils.build_local_package(ECOSYSTEM.PyPI, "numpy", "2.3.5"), True, None),
        (utils.build_local_package(ECOSYSTEM.PyPI, "pynamodb", "foo"), True, None),

    ]
)
def test_verify_positive_result(
    package: Package,
    unverifiable: bool,
    findings: Optional[list[tuple[FindingSeverity, str]]],
):
    """
    Test that `FindingsListVerifier.verify()` returns the expected findings.
    """
    backend_test_verify(package, unverifiable, findings)


@pytest.mark.parametrize(
    "package",
    [
        Package(ECOSYSTEM.Npm, "react", "18.0.0"),
        Package(ECOSYSTEM.Npm, "axios", "foo"),
        Package(ECOSYSTEM.PyPI, "packaging", "foo"),
    ]
)
def test_verify_negative_result(package: Package):
    """
    Test that `FindingsListVerifier.verify()` does not return any findings
    when there are none that match.
    """
    backend_test_verify(package, False, [])


def backend_test_verify(
    package: Package,
    unverifiable: bool,
    findings: Optional[list[tuple[FindingSeverity, str]]] = None,
):
    """
    Backend testing function for `FindingsListVerifier.verify()`.
    """
    findings_map = FindingsMap.from_yaml(FINDINGS_LIST_1)
    findings_map.merge(FindingsMap.from_yaml(FINDINGS_LIST_2))

    # Install a crafted `FindingsMap` instance for testing
    list_verifier = FindingsListVerifier()
    list_verifier._findings_map = findings_map

    if unverifiable:
        assert findings is None
        with pytest.raises(UnverifiablePackage):
            _ = list_verifier.verify(package)
        return

    assert findings is not None
    assert list_verifier.verify(package) == {
        Finding(list_verifier.name(), severity, finding) for severity, finding in findings
    }
