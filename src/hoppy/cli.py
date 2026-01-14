import os
import shlex

import typer
from rich.console import Console
from rich.rule import Rule

from . import installer, rules
from .analyzer import Analyzer
from .core.rule import Severity
from .orchestrator import display_endpoints, get_endpoints, run_scans
from .reporting import ConsoleReporter, SliceReporter, custom_theme
from .slicing_rules import format_rules, get_slicing_rule, get_slicing_rules

app = typer.Typer(
    help="Hoppy: A deep structural security scanner for multiple programming languages"
)
console = Console(theme=custom_theme)


def _ensure_joern_installed() -> None:
    """Ensure Joern is installed before showing help."""
    if installer.get_joern_executable() is None:
        installer.ensure_joern_installed(console=console)


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to the source code to scan."),
    language: str | None = typer.Option(
        None,
        "--lang",
        "-l",
        help="Language to scan (java, csharp, python). If not provided, all rules will be run.",
    ),
    output_sarif: str | None = typer.Option(
        None, "--sarif", "-s", help="Path to save SARIF results."
    ),
    coverage: str = typer.Option(
        "precision",
        "--coverage",
        "-c",
        help="Rule coverage mode: precision or broad.",
    ),
    severity_min: str | None = typer.Option(
        None,
        "--min-severity",
        help="Minimum severity to report (info, low, medium, high, critical).",
    ),
    joern_parse_args: str | None = typer.Option(
        None,
        "--joern-parse-args",
        help=(
            "Extra frontend args passed to joern-parse "
            '(e.g. "--delombok-mode no-delombok --fetch-dependencies").'
        ),
    ),
    surface_only: bool = typer.Option(
        False,
        "--surface-only",
        help="Only identify and display the attack surface, skipping deep scans.",
    ),
    depth: int = typer.Option(
        10,
        "--depth",
        help="Max depth for call graph traversal during attack surface mapping.",
    ),
):
    """
    Performs a deep security scan on the provided codebase.
    """
    abs_path = os.path.abspath(path)

    if not os.path.exists(abs_path):
        console.print(f"[bold danger]Error:[/bold danger] Path '{abs_path}' does not exist.")
        raise typer.Exit(1)

    with Analyzer() as analyzer:
        console.print("")

        with console.status(
            f"[bold info]Analyzing Codebase at {abs_path}...[/bold info]",
            spinner="dots",
        ):
            lang_map = {
                "python": "PYTHONSRC",
                "java": "JAVASRC",
                "csharp": "CSHARP",
                "javascript": "JSSRC",
            }
            extra_args = shlex.split(joern_parse_args) if joern_parse_args else None
            analyzer.load_code(
                abs_path,
                language=lang_map.get(language.lower()) if language else None,
                joern_parse_args=extra_args,
            )

        with console.status(
            "[bold info]Identifying Attack Surface[/bold info]",
            spinner="dots",
        ):
            endpoints = get_endpoints(analyzer, language=language, depth=depth)

        display_endpoints(endpoints, console=console)

        if surface_only:
            console.print("\n", Rule(style="cyan"), "\n")
            console.print("[bold success]Attack Surface Identified.[/bold success]\n")
            return

        scans = rules.get_scan_rules(language, coverage=coverage)

        reporters = [ConsoleReporter(console=console, base_path=abs_path)]

        if output_sarif:
            from .reporting import SarifReporter

            reporters.append(SarifReporter(output_sarif, base_path=abs_path))

        min_sev = Severity.from_value(severity_min) if severity_min else None

        # Use a mutable container to store the status context
        status_context = [None]

        def update_status(msg):
            if status_context[0]:
                status_context[0].update(f"[bold info]{msg}[/bold info]")

        with console.status(
            "[bold info]Running security scans[/bold info]", spinner="dots"
        ) as status:
            status_context[0] = status
            run_scans(
                analyzer,
                scans,
                reporters,
                status_callback=update_status,
                severity_min=min_sev,
            )

        console.print("\n", Rule(style="cyan"), "\n")
        console.print("[bold success]Analysis Complete.[/bold success]\n")


@app.command()
def slice(
    path: str = typer.Argument(".", help="Path to the source code to analyze."),
    sink: str | None = typer.Option(
        None,
        "--sink",
        "-s",
        help="Regex pattern for sink calls (name or code).",
    ),
    rule: str | None = typer.Option(
        None,
        "--rule",
        "-r",
        help="Named slicing rule to use (see --list-rules).",
    ),
    language: str | None = typer.Option(
        None,
        "--lang",
        "-l",
        help="Language filter for slicing rules (java, csharp, python).",
    ),
    coverage: str = typer.Option(
        "precision",
        "--coverage",
        "-c",
        help="Rule coverage mode: precision, broad, or all.",
    ),
    list_rules: bool = typer.Option(
        False,
        "--list-rules",
        help="List available slicing rules and exit.",
    ),
    depth: int = typer.Option(12, "--depth", help="Max slice depth."),
    max_sinks: int = typer.Option(6, "--max-sinks", help="Max sinks to show."),
    max_paths: int = typer.Option(4, "--max-paths", help="Max paths per sink."),
    show_paths: bool = typer.Option(
        True,
        "--show-paths/--no-paths",
        help="Show full path context for each sink.",
    ),
    joern_parse_args: str | None = typer.Option(
        None,
        "--joern-parse-args",
        help=(
            "Extra frontend args passed to joern-parse "
            '(e.g. "--delombok-mode no-delombok --fetch-dependencies").'
        ),
    ),
):
    """
    Performs program slicing from sinks to discover potential bug sources.
    """
    if list_rules:
        console.print("[bold]Available slicing rules[/bold]")
        for line in format_rules(get_slicing_rules(language, coverage=coverage)):
            console.print(f"- {line}")
        raise typer.Exit(0)

    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        console.print(f"[bold danger]Error:[/bold danger] Path '{abs_path}' does not exist.")
        raise typer.Exit(1)

    selected_rule = None
    if rule:
        selected_rule = get_slicing_rule(rule, language=language, coverage=coverage)
        if not selected_rule:
            console.print(
                f"[bold danger]Error:[/bold danger] Unknown rule '{rule}'. Use --list-rules."
            )
            raise typer.Exit(1)

    if not sink and not selected_rule:
        console.print("[bold danger]Error:[/bold danger] Provide --sink or --rule.")
        raise typer.Exit(1)

    if selected_rule:
        sink_pattern = selected_rule.sink_pattern
        rule_name = selected_rule.name
    else:
        sink_pattern = sink
        rule_name = "custom"
    assert sink_pattern is not None

    with Analyzer() as analyzer:
        console.print("")
        console.print(
            Rule(
                f"[bold cyan]Hoppy Program Slicing - {os.path.basename(abs_path)}[/bold cyan]",
                style="cyan",
            )
        )
        console.print("")

        with console.status(
            f"[bold info]Analyzing Codebase at {abs_path}...[/bold info]",
            spinner="dots",
        ):
            lang_map = {
                "python": "PYTHONSRC",
                "java": "JAVASRC",
                "csharp": "CSHARP",
                "javascript": "JSSRC",
            }
            extra_args = shlex.split(joern_parse_args) if joern_parse_args else None
            analyzer.load_code(
                abs_path,
                language=lang_map.get(language.lower()) if language else None,
                joern_parse_args=extra_args,
            )

        console.print(
            f"\n[bold info]Rule:[/bold info] [bold]{rule_name}[/bold] "
            f"([bold]sink[/bold] = {sink_pattern})"
        )
        result = analyzer.data_flow_slice(sink_pattern, depth=depth)
        if not result:
            console.print(f"[red]Slicing failed: {result.failure()}[/red]")
            raise typer.Exit(1)

        slice_obj = result.unwrap()
        reporter = SliceReporter(
            console=console,
            max_sinks=max_sinks,
            max_paths=max_paths,
            max_depth=depth,
            show_paths=show_paths,
        )
        reporter.report(slice_obj)


def main() -> None:
    """Main entry point that ensures Joern is installed before running commands."""
    import sys

    # If no arguments provided, ensure Joern is installed then show help
    if len(sys.argv) == 1:
        _ensure_joern_installed()
        sys.argv.append("--help")
        app()
    else:
        app()


if __name__ == "__main__":
    main()
