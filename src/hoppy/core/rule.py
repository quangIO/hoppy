from dataclasses import dataclass
from enum import IntEnum

from ..dsl.query import Query


class Severity(IntEnum):
    info = 1
    low = 2
    medium = 3
    high = 4
    critical = 5

    @classmethod
    def from_value(cls, value: str) -> "Severity":
        normalized = value.lower().strip()
        try:
            return cls[normalized]
        except KeyError as exc:
            raise ValueError(f"Invalid severity '{value}'") from exc


@dataclass(frozen=True)
class ScanRule:
    name: str
    query: Query
    severity: Severity = Severity.high
    description: str | None = None
    root_cause: str | None = None
    impact: str | None = None
    rule_id: str | None = None

    def __post_init__(self):
        if isinstance(self.severity, str):
            object.__setattr__(self, "severity", Severity.from_value(self.severity))
        elif not isinstance(self.severity, Severity):
            raise ValueError(f"Invalid severity type: {type(self.severity)}")

        if self.rule_id is None:
            # Generate a simple rule ID if not provided
            object.__setattr__(self, "rule_id", self.name.replace(" ", "-").lower())

    @property
    def severity_name(self) -> str:
        return self.severity.name
