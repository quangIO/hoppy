from dataclasses import dataclass, field


@dataclass
class DiscoveryHeuristic:
    """
    Heuristics for discovering potential custom sinks.
    """

    category: str
    patterns: list[str]
    weight: int = 5  # Default weight for scoring
    suspicious_params: list[str] = field(default_factory=list)
