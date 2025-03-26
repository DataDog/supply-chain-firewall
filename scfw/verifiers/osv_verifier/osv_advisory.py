"""
Provides a representation of OSV advisories for use in `OsvVerifier`.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from cvss import CVSS2, CVSS3, CVSS4  # type: ignore


class Severity(Enum):
    """
    Represents the possible severities that an OSV advisory can have.
    """
    Non = "None"
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Critical = "Critical"

    def __lt__(self, other: "Severity") -> bool:
        """
        Compare two `Severity` instances.

        Args:
            self: The `Severity` to be compared on the left-hand side
            other: The `Severity` to be compared on the right-hand side

        Returns:
            A `bool` indicating whether `<` holds between the two given `Severity`.

        Raises:
            TypeError: The other argument given was not a `Severity`.
        """
        if self.__class__ is not other.__class__:
            raise TypeError(
                f"'<' not supported between instances of '{self.__class__}' and '{other.__class__}'"
            )

        return (self.name, other.name) in {
            ("Non", "Low"), ("Non", "Medium"), ("Non", "High"), ("Non", "Critical"),
            ("Low", "Medium"), ("Low", "High"), ("Low", "Critical"),
            ("Medium", "High"), ("Medium", "Critical"),
            ("High", "Critical")
        }

    def __str__(self) -> str:
        """
        Format a `Severity` for printing.

        Returns:
            A `str` representing the given `Severity` suitable for printing.
        """
        return self.value

    @classmethod
    def from_string(cls, s: str) -> "Severity":
        """
        Convert a string into a `Severity`.

        Args:
            s: The `str` to be converted.

        Returns:
            The `Severity` referred to by the given string.

        Raises:
            ValueError: The given string does not refer to a valid `Severity`.
        """
        mappings = {severity.value: severity for severity in cls}
        if (severity := mappings.get(s.lower().capitalize())):
            return severity
        raise ValueError(f"Invalid severity '{s}'")


class OsvSeverityType(Enum):
    """
    The various severity score types defined in the OSV standard.
    """
    CVSS_V2 = "CVSS_V2"
    CVSS_V3 = "CVSS_V3"
    CVSS_V4 = "CVSS_V4"
    Ubuntu = "Ubuntu"

    @classmethod
    def from_string(cls, s: str) -> "OsvSeverityType":
        """
        Convert a string into a `OsvSeverityType`.

        Args:
            s: The `str` to be converted.

        Returns:
            The `OsvSeverityType` referred to by the given string.

        Raises:
            ValueError: The given string does not refer to a valid `OsvSeverityType`.
        """
        mappings = {type.value: type for type in cls}
        if (type := mappings.get(s)):
            return type
        raise ValueError(f"Invalid OSV severity type '{s}'")


@dataclass(eq=True, frozen=True)
class OsvSeverityScore:
    """
    A typed severity score used in assigning severities to OSV advisories.
    """
    type: OsvSeverityType
    score: str

    @classmethod
    def from_json(cls, osv_json: dict) -> "OsvSeverityScore":
        """
        Convert a JSON-formatted OSV advisory into an `OsvSeverityScore`.

        Args:
            osv_json: The JSON-formatted OSV severity score to be converted.

        Returns:
            An `OsvSeverityScore` derived from the content of the given JSON.

        Raises:
            ValueError: The severity score was malformed or missing required information.
        """
        type = osv_json.get("type")
        score = osv_json.get("score")
        if type and score:
            return cls(type=OsvSeverityType.from_string(type), score=score)
        raise ValueError("Encountered malformed OSV severity score")

    def severity(self) -> Severity:
        """
        Return the `Severity` of the given `OsvSeverityScore`.

        Returns:
            The computed `Severity` of the given `OsvSeverityScore`.
        """
        match self.type:
            case OsvSeverityType.CVSS_V2:
                severity_str = CVSS2(self.score).severities()[0]
            case OsvSeverityType.CVSS_V3:
                severity_str = CVSS3(self.score).severities()[0]
            case OsvSeverityType.CVSS_V4:
                severity_str = CVSS4(self.score).severity
            case OsvSeverityType.Ubuntu:
                severity_str = "None" if self.score == "Negligible" else self.score

        return Severity.from_string(severity_str)


@dataclass(eq=True, frozen=True)
class OsvAdvisory:
    """
    A representation of an OSV advisory containing only the fields relevant
    to installation target verification.
    """
    id: str
    severity: Optional[Severity]

    def __lt__(self, other: "OsvAdvisory") -> bool:
        """
        Compare two `OsvAdvisory` instances on the basis of their severities.

        Args:
            self: The `OsvAdvisory` to be compared on the left-hand side
            other: The `OsvAdvisory` to be compared on the right-hand side

        Returns:
            A `bool` indicating whether `<` holds between the two given `OsvAdvisory`.

        Raises:
            TypeError: The other argument given was not an `OsvAdvisory`.
        """
        if self.__class__ is not other.__class__:
            raise TypeError(
                f"'<' not supported between instances of '{self.__class__}' and '{other.__class__}'"
            )

        # A match statement would be more natural here but mypy is not up to it
        return (
            (self.severity is None and other.severity is not None)
            or (self.severity is not None and other.severity is not None and self.severity < other.severity)
        )

    @classmethod
    def from_json(cls, osv_json: dict) -> "OsvAdvisory":
        """
        Convert a JSON-formatted OSV advisory into an `OsvAdvisory`.

        Args:
            osv_json: The JSON-formatted OSV advisory to be converted.

        Returns:
            An `OsvAdvisory` derived from the content of the given JSON.

        Raises:
            ValueError: The advisory was malformed or missing required information.
        """
        if (id := osv_json.get("id")):
            scores = list(map(OsvSeverityScore.from_json, osv_json.get("severity", [])))
            return cls(
                id=id,
                severity=max(map(lambda score: score.severity(), scores)) if scores else None
            )
        raise ValueError("Encountered OSV advisory with missing ID field")
