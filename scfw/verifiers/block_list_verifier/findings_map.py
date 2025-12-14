"""
Provides a class for reading YAML package block lists in a fixed yet flexible format
and parsing them into an efficiently queryable data structure for verification.
"""

from typing import Any, Type
from typing_extensions import Self

import yaml

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.verifier import FindingSeverity


class FindingsMap:
    """
    A class that can read YAML package block lists in a fixed yet flexible format
    and parses them into an efficiently queryable data structure for verification.
    """
    def __init__(self):
        """
        Initialize a new, empty `FindingsMap`.
        """
        self._raw_map = {}

    @classmethod
    def from_yaml(cls, yml: str) -> Self:
        """
        Initialize a `FindingsMap` from a YAML block list.

        Args:
            yml:
                A YAML `str` containing the block list to be parsed. Refer to the
                `examples/` directory for an example of the expected block list format.

        Returns:
            A `FindingsMap` initialized from the given YAML block list.
        """
        def get_or_raise(d: dict, key: str, typ: Type) -> Any:
            if key not in d:
                raise ValueError(f"Missing required key: '{key}'")

            value = d[key]
            if not isinstance(value, typ):
                raise TypeError(f"Incompatible type for '{key}' value: require {typ}")

            return value

        def check_collection(collection, typ: Type):
            if not all(isinstance(item, typ) for item in collection):
                raise ValueError(
                    f"Received heterogeneous collection (expected {type(collection)}[{typ}])"
                )

        raw_map = {}

        block_list = yaml.safe_load(yml)
        if not isinstance(block_list, dict):
            raise RuntimeError("Block list YAML file must contain a single top-level mapping")

        items = get_or_raise(block_list, "items", list)
        check_collection(items, dict)

        for item in items:
            severity = FindingSeverity.from_string(get_or_raise(item, "severity", str))
            finding = get_or_raise(item, "finding", str)

            packages = get_or_raise(item, "packages", list)
            check_collection(packages, dict)

            for entry in packages:
                ecosystem = ECOSYSTEM.from_string(get_or_raise(entry, "ecosystem", str))
                package_name = get_or_raise(entry, "name", str)

                if "versions" in entry:
                    versions = get_or_raise(entry, "versions", list)
                    check_collection(versions, str)
                else:
                    versions = ["*"]

                for version in versions:
                    version_findings = (
                        raw_map.setdefault(ecosystem, {}).setdefault(package_name, {}).setdefault(version, [])
                    )
                    version_findings.append((severity, finding))

        findings_map = cls()
        findings_map._raw_map = raw_map

        return findings_map

    def merge(self, other: Self):
        """
        Merge a second `FindingsMap` into the given one.

        Args:
            other:
                The `FindingsMap` whose contents should be merged into `self`.

                Note that no attempt is made to deduplicate the merged findings. That is,
                if `self` and `other` contain the same finding for a given package, then
                the merged `FindingsMap` contains two such findings for that package.
        """
        def insert_or_submerge(submerge, self, other):
            for key, value in other.items():
                if key not in self:
                    self[key] = value
                else:
                    submerge(self[key], value)

        def merger(submerge):
            return lambda self, other: insert_or_submerge(submerge, self, other)

        merge_package_map = merger(lambda self, other: self.extend(other))
        merge_ecosystem_map = merger(merge_package_map)

        merge_ecosystem_map(self._raw_map, other._raw_map)

    def get_findings(self, package: Package) -> list[tuple[FindingSeverity, str]]:
        """
        Return all findings in the map for a given package.

        Args:
            package: The `Package` whose findings are to be queried.

        Returns:
            A list of findings pertaining to the given package present in the map.

            This list of findings contains those pertaining to the precise triple of
            ecosystem-name-version described by `package` *as well as* any declared findings
            pertaining to any version of `package` that may have been present in the
            input block list(s) from which the `FindingsMap` was generated.
        """
        package_findings = self._raw_map.get(package.ecosystem, {}).get(package.name, {})
        if not package_findings:
            return []

        return package_findings.get("*", []) + package_findings.get(package.version, [])
