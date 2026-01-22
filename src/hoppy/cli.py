import os
import re
import shlex

import typer
from rich.console import Console
from rich.rule import Rule

from . import installer, rules
from .analyzer import Analyzer
from .core.rule import Confidence, Severity
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
    confidence_min: str | None = typer.Option(
        None,
        "--min-confidence",
        help="Minimum confidence to report (low, medium, high).",
    ),
    joern_parse_args: str | None = typer.Option(
        None,
        "--joern-parse-args",
        help=(
            "Extra frontend args passed to joern-parse "
            '(e.g. "--delombok-mode no-delombok --fetch-dependencies").'
        ),
    ),
    use_cache: bool = typer.Option(
        True,
        "--cache/--no-cache",
        help="Use cached CPG if available and source hasn't changed.",
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
    max_findings: int = typer.Option(
        3,
        "--max-findings",
        help="Maximum number of findings to report per rule per file.",
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
            res = analyzer.load_code(
                abs_path,
                language=lang_map.get(language.lower()) if language else None,
                joern_parse_args=extra_args,
                use_cache=use_cache,
            )
            if not res:
                console.print(f"[bold danger]Error loading code:[/bold danger] {res.failure()}")
                raise typer.Exit(1)

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

        reporters = [
            ConsoleReporter(console=console, base_path=abs_path, max_findings=max_findings)
        ]

        if output_sarif:
            from .reporting import SarifReporter

            reporters.append(SarifReporter(output_sarif, base_path=abs_path))

        min_sev = Severity.from_value(severity_min) if severity_min else None
        min_conf = Confidence.from_value(confidence_min) if confidence_min else None

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
                confidence_min=min_conf,
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


@app.command()
def discover(
    path: str = typer.Argument(".", help="Path to the source code to scan."),
    language: str | None = typer.Option(
        None,
        "--lang",
        "-l",
        help="Language to scan (java, csharp, python).",
    ),
    joern_parse_args: str | None = typer.Option(
        None,
        "--joern-parse-args",
        help="Extra frontend args passed to joern-parse.",
    ),
):
    """
    Discover potential custom sinks (wrappers around dangerous APIs).
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

        from .rules import get_discovery_heuristics

        heuristics = get_discovery_heuristics(language)
        if not heuristics:
            console.print(
                f"[yellow]Warning:[/yellow] No discovery heuristics available for "
                f"language '{language or 'unknown'}'. Using default empty list."
            )

        result = analyzer.discover_wrappers(heuristics)
        if not result:
            console.print(f"[red]Discovery failed: {result.failure()}[/red]")
            raise typer.Exit(1)

        wrappers = result.unwrap()
        # Sort by score descending
        wrappers.sort(key=lambda x: x.get("score", 0), reverse=True)

        console.print(f"\n[bold]Discovered {len(wrappers)} potential custom sinks:[/bold]\n")

        for w in wrappers:
            # Collect all tainted params
            all_tainted = set()
            for call in w["dangerousCalls"]:
                all_tainted.update(call.get("taintedBy", []))

            # Format params
            param_strs = []
            for p in w["params"]:
                if p in all_tainted:
                    param_strs.append(f"[red]{p}[/red]")
                else:
                    param_strs.append(p)

            param_display = ", ".join(param_strs)
            loc = f"{os.path.basename(w['file'])}:{w['line']}"

            console.print(f"[bold cyan]{w['name']}[/bold cyan] ({param_display}) [dim]{loc}[/dim]")

            # Group calls by category
            cat_calls = {}
            for call in w["dangerousCalls"]:
                cat = call["category"]
                if cat not in cat_calls:
                    cat_calls[cat] = []
                cat_calls[cat].append(f"`{call['fullName']}`")

            for cat, calls in sorted(cat_calls.items()):
                calls_str = ", ".join(calls)
                console.print(f"  ↳ [yellow]{cat}[/yellow]: calls {calls_str}")
            console.print("")


@app.command(name="call-graph")
def call_graph_cmd(
    path: str = typer.Argument(".", help="Path to the source code."),
    method: str | None = typer.Option(
        None, "--method", "-m", help="Full name of the starting method."
    ),
    pattern: str = typer.Option(
        ".*", "--pattern", "-p", help="Pattern to match method names (if --method not specified)."
    ),
    file_pattern: str = typer.Option(".*", "--file", "-f", help="Pattern to match file names."),
    direction: str = typer.Option(
        "callee", "--direction", "-d", help="Direction: 'caller' or 'callee'."
    ),
    depth: int = typer.Option(5, "--depth", help="Max depth for traversal."),
    exclude: list[str] | None = typer.Option(None, "--exclude", "-e", help="Patterns to exclude."),
    include_external: str | None = typer.Option(
        None, "--include-external", help="Pattern for external methods to include in the graph."
    ),
    language: str | None = typer.Option(None, "--lang", "-l", help="Language filter."),
    display_conditions: bool = typer.Option(
        False, "--display-conditions", help="Show logical conditions (IF structures) guarding calls."
    ),
    backward_trace: bool = typer.Option(
        False, "--backward-trace", help="Trace interesting sink arguments back to method parameters."
    ),
    summary: bool = typer.Option(
        False, "--summary", help="Show a security overview table at the end."
    ),
):
    """
    Displays call graphs starting from matching methods.
    """
    with Analyzer() as analyzer:
        lang_map = {
            "python": "PYTHONSRC",
            "java": "JAVASRC",
            "csharp": "CSHARP",
            "javascript": "JSSRC",
        }
        analyzer.load_code(
            os.path.abspath(path),
            language=lang_map.get(language.lower()) if language else None,
        )

        if method:
            start_methods = [method]
        else:
            # Discover matching methods
            with console.status("[bold info]Finding matching methods...[/bold info]"):
                res = analyzer.list_methods(
                    pattern=pattern, file_pattern=file_pattern, internal_only=True
                )
                if not res:
                    console.print(f"[red]Failed to find methods: {res.failure()}[/red]")
                    return
                start_methods = res.unwrap()

        if not start_methods:
            console.print("[yellow]No matching methods found.[/yellow]")
            return

        from .rules import AuthBarrier, get_discovery_heuristics

        heuristics = get_discovery_heuristics(language)
        barrier_pattern = AuthBarrier()
        barrier_pred = barrier_pattern.to_cpg_predicate()

        # Default exclusions for standard libraries
        default_excludes = [
            r"java\..*",
            r"javax\..*",
            r"sun\..*",
            r"jdk\..*",
            r"org\.springframework\..*",
            r"posix\..*",
            r"nt\..*",
            r"_.*",  # Python internals
            r"typing\..*",
            r"abc\..*",
            r"genericpath\..*",
            r"axios\..*",
            r"fs\..*",
            r"path\..*",
        ]
        all_excludes = default_excludes + (exclude or [])

        # For security summary
        security_findings = []

        def print_node(node, current_depth=0, is_last=True, prefix="", root_method=None):
            connector = "└── " if is_last else "├── "
            color = "cyan" if current_depth == 0 else "white"

            if current_depth == 0:
                root_method = node["name"]

            # Check if this node is interesting (matches a dangerous pattern)
            category = node.get("category")
            if category:
                color = "yellow"
                
                # Use callerFile if the sink's own file is empty (common for external libraries)
                location = node.get("file")
                if not location or location == "<empty>":
                    location = node.get("callerFile", "unknown")
                
                security_findings.append({
                    "entry": root_method,
                    "sink": node["name"],
                    "category": category,
                    "file": location
                })

            label = f"[{color}]{node['name']}[/{color}] [dim]({node['fullName']})[/dim]"
            if category:
                label += f" [bold yellow]\\[{category}][/bold yellow]"

            # Display real barrier snippets
            barriers = node.get("barriers")
            if barriers:
                cleaned = []
                for b in barriers:
                    c = re.sub(r"\s+", " ", b).strip()
                    if len(c) > 60:
                        c = c[:57] + "..."
                    cleaned.append(c)
                barrier_str = ", ".join(cleaned)
                label += f" [bold green]\\[GUARD: {barrier_str}][/bold green]"

            # Display traces
            traces = node.get("traces")
            if traces:
                trace_lines = []
                for t in traces:
                    trace_lines.append(f"[bold magenta]    ↳ {t}[/bold magenta]")
                label += "\n" + "\n".join([f"{prefix}│   {tl}" for tl in trace_lines])

            # Display real inline conditions if requested
            if display_conditions:
                conditions = node.get("conditions")
                if conditions:
                    cleaned_conds = []
                    for cond in conditions:
                        c = re.sub(r"\s+", " ", cond).strip()
                        if len(c) > 60:
                            c = c[:57] + "..."
                        cleaned_conds.append(c)
                    cond_str = ", ".join(cleaned_conds)
                    label += f" [bold blue]\\[IF: {cond_str}][/bold blue]"

            console.print(f"{prefix}{connector}{label}")

            new_prefix = prefix + ("    " if is_last else "│   ")
            children = node.get("children", [])
            for i, child in enumerate(children):
                print_node(child, current_depth + 1, i == len(children) - 1, new_prefix, root_method=root_method)

        barrier_heuristics = rules.get_barrier_heuristics(language)
        with console.status("[bold info]Traversing call graphs...[/bold info]"):
            result = analyzer.get_call_graph(
                start_methods,
                direction=direction,
                depth=depth,
                exclude_patterns=all_excludes,
                heuristics=heuristics,
                barrier_heuristics=barrier_heuristics,
                barrier_predicate=barrier_pred,
                include_conditions=display_conditions,
                include_backward_trace=backward_trace,
                include_external_pattern=include_external,
            )

        if not result:
            console.print(f"[red]Failed to retrieve call graphs: {result.failure()}[/red]")
            return

        trees = result.unwrap()

        def count_interesting(node):
            count = 1 if node.get("category") else 0
            for child in node.get("children", []):
                count += count_interesting(child)
            return count

        # Sort trees by number of interesting nodes (descending)
        trees.sort(key=count_interesting, reverse=True)

        for tree in trees:
            if not tree or not tree.get("children"):
                continue

            print_node(tree)
            console.print("")

        if summary:
            if security_findings:
                from rich.tree import Tree
                summary_tree = Tree("[bold magenta]Security Summary[/bold magenta]")
                
                # Group by Category -> Sink -> (Entry + File)
                grouped = {}
                for f in security_findings:
                    cat = f["category"]
                    sink = f["sink"]
                    entry = f["entry"]
                    loc = f["file"]
                    
                    if cat not in grouped:
                        grouped[cat] = {}
                    if sink not in grouped[cat]:
                        grouped[cat][sink] = set()
                    # Deduplicate entry points per sink
                    grouped[cat][sink].add(f"{entry} [dim]({loc})[/dim]")

                for cat, sinks in sorted(grouped.items()):
                    cat_node = summary_tree.add(f"[bold yellow]{cat}[/bold yellow]")
                    for sink, entries in sorted(sinks.items()):
                        sink_node = cat_node.add(f"[bold red]{sink}[/bold red]")
                        for entry_info in sorted(entries):
                            sink_node.add(entry_info)
                
                console.print(summary_tree)
            else:
                console.print("[bold green]No dangerous sinks identified in the explored paths.[/bold green]")


@app.command(name="list-methods")
def list_methods_cmd(
    path: str = typer.Argument(".", help="Path to the source code to analyze."),
    pattern: str = typer.Option(".*", "--pattern", "-p", help="Regex pattern for method names."),
    calls: bool = typer.Option(
        False, "--calls", "-c", help="List called methods instead of definitions."
    ),
    external: bool = typer.Option(
        False, "--external", "-e", help="List only external/library calls (API summary)."
    ),
    language: str | None = typer.Option(
        None, "--lang", "-l", help="Language filter (java, csharp, python, javascript)."
    ),
    joern_parse_args: str | None = typer.Option(
        None,
        "--joern-parse-args",
        help="Extra frontend args passed to joern-parse.",
    ),
):
    """
    Lists methods (definitions or calls) in the codebase.
    Useful for discovering dangerous sinks.
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

        if external:
            result = analyzer.get_api_summary()
            if not result:
                console.print(f"[red]Failed to get API summary: {result.failure()}[/red]")
                raise typer.Exit(1)

            summary = result.unwrap()
            console.print("\n[bold]External API Calls (grouped by module):[/bold]\n")
            import re

            pat = re.compile(pattern, re.IGNORECASE)

            for module, methods in sorted(summary.items()):
                filtered = [m for m in methods if pat.search(m)]
                if filtered:
                    console.print(f"[bold cyan]{module}[/bold cyan]")
                    for m in sorted(filtered):
                        console.print(f"  {m}")
            return

        if calls:
            result = analyzer.list_calls(pattern)
            title = "Called Methods"
        else:
            result = analyzer.list_methods(pattern)
            title = "Method Definitions"

        if not result:
            console.print(f"[red]Failed to list methods: {result.failure()}[/red]")
            raise typer.Exit(1)

        methods = result.unwrap()

        # Group by simple name for better discovery
        grouped = {}
        for m in methods:
            # Heuristic extraction of simple name
            parts = m.split(":")
            candidate = parts[-1]

            # If candidate looks like a signature (has parens), try previous part
            if "(" in candidate or ")" in candidate:
                if len(parts) > 1:
                    candidate = parts[-2]

            # If candidate is a path/package, take the last part
            if "/" in candidate:
                candidate = candidate.split("/")[-1]
            if "." in candidate:
                candidate = candidate.split(".")[-1]

            grouped.setdefault(candidate, []).append(m)

        console.print(f"\n[bold]{title} matching '{pattern}' (grouped by name):[/bold]\n")

        for name in sorted(grouped.keys()):
            console.print(f"[bold cyan]{name}[/bold cyan]")
            for m in sorted(grouped[name]):
                console.print(f"  {m}")


@app.command(name="method-details")
def method_details_cmd(
    path: str = typer.Argument(".", help="Path to the source code."),
    name: str = typer.Option(..., "--name", "-n", help="Full name of the method to inspect."),
    language: str | None = typer.Option(None, "--lang", "-l", help="Language filter."),
):
    """
    Shows detailed information about a specific method.
    """
    with Analyzer() as analyzer:
        lang_map = {
            "python": "PYTHONSRC",
            "java": "JAVASRC",
            "csharp": "CSHARP",
            "javascript": "JSSRC",
        }
        analyzer.load_code(
            os.path.abspath(path),
            language=lang_map.get(language.lower()) if language else None,
        )

        result = analyzer.get_method_details(name)
        if not result or result.unwrap() is None:
            console.print(f"[red]Method '{name}' not found.[/red]")
            return

        details = result.unwrap()
        console.print(f"\n[bold cyan]Method:[/bold cyan] [bold]{details['fullName']}[/bold]")
        console.print(f"[bold info]File:[/bold info] {details['file']}:{details['line']}")

        if details.get("params"):
            console.print("\n[bold]Parameters:[/bold]")
            for p in details["params"]:
                console.print(f"  - {p['name']} ({p['type']})")

        if details.get("callsOut"):
            console.print("\n[bold]Calls Made:[/bold]")
            # Group by fullName to avoid noise
            seen_calls = {}
            for c in details["callsOut"]:
                seen_calls.setdefault(c["fullName"], []).append(c["code"])

            for fn, codes in sorted(seen_calls.items()):
                console.print(f"  - [bold]{fn}[/bold]")
                for code in sorted(list(set(codes)))[:3]:
                    console.print(f"    [dim]{code}[/dim]")

        if details.get("callers"):
            console.print("\n[bold]Called By:[/bold]")
            for c in sorted(details["callers"]):
                console.print(f"  - {c}")

        if details.get("code"):
            console.print("\n[bold]Source Code:[/bold]")
            from rich.syntax import Syntax

            syntax = Syntax(
                details["code"], language or "python", theme="monokai", line_numbers=True
            )
            console.print(syntax)


@app.command(name="find-calls")
def find_calls_cmd(
    path: str = typer.Argument(".", help="Path to the source code."),
    pattern: str = typer.Option(
        ".*", "--pattern", "-p", help="Regex pattern for called method names."
    ),
    language: str | None = typer.Option(None, "--lang", "-l", help="Language filter."),
):
    """
    Finds rich information about call sites matching a pattern.
    """
    with Analyzer() as analyzer:
        lang_map = {
            "python": "PYTHONSRC",
            "java": "JAVASRC",
            "csharp": "CSHARP",
            "javascript": "JSSRC",
        }
        analyzer.load_code(
            os.path.abspath(path),
            language=lang_map.get(language.lower()) if language else None,
        )

        result = analyzer.find_calls(pattern)
        if not result:
            console.print(f"[red]Failed to find calls: {result.failure()}[/red]")
            return

        calls = result.unwrap()
        console.print(f"\n[bold]Call sites matching '{pattern}':[/bold]\n")

        from rich.table import Table

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Location", style="dim")
        table.add_column("Caller", style="cyan")
        table.add_column("Code", style="green")

        for c in sorted(calls, key=lambda x: (x["file"], x["line"])):
            loc = f"{os.path.basename(c['file'])}:{c['line']}"
            table.add_row(loc, c["caller"], c["code"])

        console.print(table)


@app.command(name="query")
def query_cmd(
    scala: str = typer.Argument(..., help="Raw Scala query to execute."),
    path: str = typer.Option(".", help="Path to the source code."),
    language: str | None = typer.Option(None, "--lang", "-l", help="Language filter."),
):
    """
    Executes a raw Scala query against the CPG.
    """
    with Analyzer() as analyzer:
        lang_map = {
            "python": "PYTHONSRC",
            "java": "JAVASRC",
            "csharp": "CSHARP",
            "javascript": "JSSRC",
        }
        analyzer.load_code(
            os.path.abspath(path),
            language=lang_map.get(language.lower()) if language else None,
        )

        result = analyzer.raw_scala(scala, prelude=analyzer.session.prelude)
        if not result:
            console.print(f"[red]Query failed: {result.failure()}[/red]")
            return

        console.print("\n[bold]Query Result:[/bold]\n")
        console.print(result.unwrap())


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
