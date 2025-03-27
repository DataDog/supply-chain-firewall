"""
Provides a representation of OSV advisories for use in `OsvVerifier`.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
from typing_extensions import Self

from cvss import CVSS2, CVSS3, CVSS4  # type: ignore


class Severity(Enum):
    """
    Represents the possible severities that an OSV advisory can have.
    """
    Non = 0
    Low = 1
    Medium = 2
    High = 3
    Critical = 4

    def __lt__(self, other: Self) -> bool:
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

        return self.value < other.value

    def __str__(self) -> str:
        """
        Format a `Severity` for printing.

        Returns:
            A `str` representing the given `Severity` suitable for printing.
        """
        return "None" if self.name == "Non" else self.name

    @classmethod
    def from_string(cls, s: str) -> Self:
        """
        Convert a string into a `Severity`.

        Args:
            s: The `str` to be converted.

        Returns:
            The `Severity` referred to by the given string.

        Raises:
            ValueError: The given string does not refer to a valid `Severity`.
        """
        mappings = {f"{severity}".lower(): severity for severity in cls}
        if (severity := mappings.get(s.lower())):
            return severity
        raise ValueError(f"Invalid severity '{s}'")


class OsvSeverityType(str, Enum):
    """
    The various severity score types defined in the OSV standard.
    """
    CVSS_V2 = "CVSS_V2"
    CVSS_V3 = "CVSS_V3"
    CVSS_V4 = "CVSS_V4"
    Ubuntu = "Ubuntu"


@dataclass(eq=True, frozen=True)
class OsvSeverityScore:
    """
    A typed severity score used in assigning severities to OSV advisories.
    """
    type: OsvSeverityType
    score: str

    @classmethod
    def from_json(cls, osv_json: dict) -> Self:
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
            return cls(type=OsvSeverityType(type), score=score)
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

    @classmethod
    def compare_severities(cls, lhs: Self, rhs: Self) -> int:
        """
        Compare two `OsvAdvisory` instances on the basis of their severities such that
        advisories with no severities are sorted lower than those with severities.

        Args:
            self: The `OsvAdvisory` to be compared on the left-hand side
            other: The `OsvAdvisory` to be compared on the right-hand side

        Returns:
            An `int` indicating whether the first `OsvAdvisory` is less than, equal to
            or greater than the second one.

        Raises:
            TypeError: One of the given arguments is not an `OsvAdvisory`.
        """
        if not (isinstance(lhs, cls) and isinstance(rhs, cls)):
            raise TypeError("Received incompatible argument types while comparing OSV severities")

        # A match statement would be more natural here but mypy is not up to it
        if lhs.severity == rhs.severity:
            result = 0
        elif lhs.severity is None:
            result = -1
        elif rhs.severity is None:
            result = 1
        elif lhs.severity < rhs.severity:
            result = -1
        elif rhs.severity < lhs.severity:
            result = 1

        return result

    @classmethod
    def from_json(cls, osv_json: dict) -> Self:
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
