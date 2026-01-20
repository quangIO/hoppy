from ..core.rule import ScanRule, Severity
from ..dsl.patterns import Or, Pattern
from ..dsl.query import Query
from . import csharp, java, javascript, python
from .common import Sanitizer
from .discovery import DiscoveryHeuristic


def SqlSink(coverage: str = "precision") -> Pattern:  # noqa: N802
    """Cross-language SQL injection sinks."""
    return Or(
        [
            java.SqlSink(coverage),
            csharp.SqlSink(),
            python.SqlSink(),
            javascript.SqlSink(coverage),
        ]
    )


def StackedSqlSink() -> Pattern:  # noqa: N802
    """Cross-language stacked query sinks."""
    return Or(
        [
            python.StackedSqlSink(),
            javascript.StackedSqlSink(),
        ]
    )


def CommandSink() -> Pattern:  # noqa: N802
    """Cross-language command injection sinks."""
    return Or([java.CommandSink(), python.CommandSink(), javascript.CommandSink()])


def SsrfSink(coverage: str = "precision") -> Pattern:  # noqa: N802
    """Cross-language SSRF sinks."""
    return Or(
        [
            java.SsrfSink(coverage),
            csharp.SsrfSink(coverage),
            python.SsrfSink(),
            javascript.SsrfSink(coverage),
        ]
    )


def ArchiveExtractionSink(coverage: str = "precision") -> Pattern:  # noqa: N802
    """Cross-language archive extraction sinks."""
    return Or(
        [
            java.ArchiveExtractionSink(coverage),
            csharp.ArchiveExtractionSink(coverage),
            python.ArchiveExtractionSink(coverage),
            javascript.ArchiveExtractionSink(coverage),
        ]
    )


def UnsafePopulationSink() -> Pattern:  # noqa: N802
    """Cross-language mass assignment sinks."""
    return Or(
        [
            java.UnsafePopulationSink(),
            csharp.UnsafePopulationSink(),
            python.UnsafePopulationSink(),
            javascript.UnsafePopulationSink(),
        ]
    )


def WebSource(var_name: str = "$IN") -> Pattern:  # noqa: N802
    """
    Matches untrusted web inputs across different frameworks.
    """
    return Or(
        [
            java.WebSource(var_name),
            csharp.WebSource(var_name),
            python.WebSource(var_name),
            javascript.WebSource(var_name),
        ]
    )


def Controller() -> Pattern:  # noqa: N802
    """
    Matches web controller methods across languages.
    """
    return Or(
        [
            java.Controller(),
            csharp.Controller(),
            python.Controller(),
            javascript.Controller(),
        ]
    )


def AuthBarrier() -> Pattern:  # noqa: N802
    """
    Matches authentication barriers across languages.
    """
    return Or(
        [
            java.AuthBarrier(),
            csharp.AuthBarrier(),
            python.AuthBarrier(),
            javascript.AuthBarrier(),
        ]
    )


def AuthBypass() -> Pattern:  # noqa: N802
    """
    Matches explicit authentication bypasses across languages.
    """
    return Or(
        [
            java.AuthBypass(),
            csharp.AuthBypass(),
            python.AuthBypass(),
            javascript.AuthBypass(),
        ]
    )


def Authenticated(pattern: Pattern) -> Pattern:  # noqa: N802
    """
    Matches nodes that are dominated by an authentication barrier.
    """
    return pattern.is_dominated_by(AuthBarrier())


def Unauthenticated(pattern: Pattern) -> Pattern:  # noqa: N802
    """
    Matches nodes that are NOT dominated by an authentication barrier.
    """
    return pattern.is_not_dominated_by(AuthBarrier())


def get_scan_rules(language: str | None = None, coverage: str = "precision") -> list[ScanRule]:
    """
    Returns common security scan rules.
    """
    if language == "java":
        return java.get_scan_rules(coverage)
    if language == "csharp":
        return csharp.get_scan_rules(coverage)
    if language == "python":
        return python.get_scan_rules(coverage)
    if language == "javascript":
        return javascript.get_scan_rules(coverage)

    # Generic cross-language rules
    source = WebSource("$IN")
    sanitizer = Sanitizer()

    return [
        ScanRule(
            name="SQL Injection",
            query=Query.source(source).flows_to(SqlSink(coverage)).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="User input reaches a SQL execution sink without proper "
            "parameterization or sanitization.",
            impact="Unauthorized data access or database compromise.",
        ),
        ScanRule(
            name="SQL Injection (Stacked Queries)",
            query=Query.source(source).flows_to(StackedSqlSink()).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="User input reaches a SQL API that executes multiple statements.",
            impact="Attackers can chain statements (e.g., DROP/UPDATE) after the intended query.",
        ),
        ScanRule(
            name="Command Injection",
            query=Query.source(source).flows_to(CommandSink()).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="User input is used to construct a system command.",
            impact="Remote Code Execution (RCE).",
        ),
        ScanRule(
            name="Server-Side Request Forgery (SSRF)",
            query=Query.source(source).flows_to(SsrfSink(coverage)).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="User input influences the destination of a network request.",
            impact="Internal network exposure or data exfiltration.",
        ),
        ScanRule(
            name="Unsafe Population (Mass Assignment)",
            query=Query.source(source).flows_to(UnsafePopulationSink()),
            severity=Severity.medium,
            root_cause="Untrusted input is used to populate multiple fields of an object at once.",
            impact="Unauthorized modification of sensitive fields.",
        ),
        ScanRule(
            name="Missing Authentication for Sensitive Sink",
            query=Query.source(
                (SqlSink() | CommandSink() | SsrfSink()).is_not_dominated_by(AuthBarrier())
            ),
            severity=Severity.high,
            root_cause="A sensitive operation is performed without an "
            "preceding authentication check.",
            impact="Unauthorized access to critical functionality.",
        ),
    ]


def get_discovery_heuristics(language: str | None = None) -> list[DiscoveryHeuristic]:
    """
    Returns discovery heuristics for the specified language.
    """
    if language == "python":
        return python.get_discovery_heuristics()
    if language == "javascript":
        return javascript.get_discovery_heuristics()
    if language == "java":
        return java.get_discovery_heuristics()
    if language == "csharp":
        return csharp.get_discovery_heuristics()
    return []
