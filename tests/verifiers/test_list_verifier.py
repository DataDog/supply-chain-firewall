"""
Tests of `FindingsListVerifier`.
"""

import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity
from scfw.verifiers.list_verifier import FindingsListVerifier, FindingsMap

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
    "ecosystem, name, version, findings",
    [
        (
            ECOSYSTEM.Npm,
            "react",
            "18.2.0",
            [(FindingSeverity.CRITICAL, "This is a critical finding in the second test findings list")],
        ),
        (
            ECOSYSTEM.Npm,
            "react",
            "18.3.0",
            [(FindingSeverity.CRITICAL, "This is a critical finding in the first test findings list")],
        ),
        (
            ECOSYSTEM.PyPI,
            "numpy",
            "foo",
            [(FindingSeverity.WARNING, "This is a warning finding in the first test findings list")],
        ),
        (
            ECOSYSTEM.PyPI,
            "numpy",
            "2.3.5",
            [
                (FindingSeverity.WARNING, "This is a warning finding in the first test findings list"),
                (FindingSeverity.CRITICAL, "This is another critical finding in the second test findings list"),
                (FindingSeverity.WARNING, "This is a warning finding in the second test findings list"),
            ],
        ),
        (
            ECOSYSTEM.PyPI,
            "pynamodb",
            "foo",
            [(FindingSeverity.CRITICAL, "This is a critical finding in the first test findings list")],
        ),
    ]
)
def test_verify_positive_result(
    ecosystem: ECOSYSTEM,
    name: str,
    version: str,
    findings: list[tuple[FindingSeverity, str]],
):
    """
    Test that `FindingsListVerifier.verify()` returns the expected findings.
    """
    backend_test_verify(ecosystem, name, version, findings)


@pytest.mark.parametrize(
    "ecosystem, name, version",
    [
        (ECOSYSTEM.Npm, "react", "18.0.0"),
        (ECOSYSTEM.Npm, "axios", "foo"),
        (ECOSYSTEM.PyPI, "packaging", "foo"),
    ]
)
def test_verify_negative_result(ecosystem: ECOSYSTEM, name: str, version: str):
    """
    Test that `FindingsListVerifier.verify()` does not return any findings
    when there are none that match.
    """
    backend_test_verify(ecosystem, name, version)


def backend_test_verify(
    ecosystem: ECOSYSTEM,
    name: str,
    version: str,
    findings: list[tuple[FindingSeverity, str]] = [],
):
    """
    Backend testing function for `FindingsListVerifier.verify()`.
    """
    findings_map = FindingsMap.from_yaml(FINDINGS_LIST_1)
    findings_map.merge(FindingsMap.from_yaml(FINDINGS_LIST_2))

    # Install a crafted `FindingsMap` instance for testing
    list_verifier = FindingsListVerifier()
    list_verifier._findings_map = findings_map

    assert list_verifier.verify(Package(ecosystem, name, version)) == findings
