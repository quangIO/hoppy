from dataclasses import dataclass, field

from rich.console import Console
from rich.tree import Tree

from . import rules, slicing_rules
from .analyzer import Analyzer
from .core.rule import ScanRule, Severity
from .dsl.patterns import Return, _esc
from .dsl.query import Query
from .reporting import Reporter


@dataclass
class Endpoint:
    controller: str
    action: str
    fullname: str
    is_protected: bool
    capabilities: dict[str, list[str]] = field(default_factory=dict)


def display_endpoints(endpoints: list[Endpoint], console: Console | None = None):
    """
    Displays a tree of endpoints and their authentication status.
    """
    console = console or Console()
    root = Tree("[bold magenta]Attack Surface[/bold magenta]", guide_style="bright_blue")

    # Group by controller
    by_controller = {}
    for e in endpoints:
        by_controller.setdefault(e.controller, []).append(e)

    for controller in sorted(by_controller.keys()):
        # Prettify controller name
        if "::program:" in controller:
            display_name = controller.split("::program:")[-1]
        elif ":" in controller:
            display_name = controller.split(":")[-1]
        else:
            display_name = controller.split(".")[-1]

        c_node = root.add(f"[bold cyan]{display_name}[/bold cyan]")

        for e in sorted(by_controller[controller], key=lambda x: x.action):
            status = (
                "[bold green]PROTECTED[/bold green]"
                if e.is_protected
                else "[bold yellow]🔓 PUBLIC[/bold yellow]"
            )

            cap_str = ""
            if e.capabilities:
                # Use icons for capabilities
                icons = {
                    "File System": "📁",
                    "Database": "🗄️",
                    "Network": "🌐",
                    "Command Execution": "💻",
                    "Code Execution": "⚡",
                    "Cryptography": "🔐",
                }
                caps = []
                for cap, evidence in e.capabilities.items():
                    evidence_str = f" ({', '.join(evidence[:3])})" if evidence else ""
                    caps.append(f"[blue]{icons.get(cap, '')} {cap}{evidence_str}[/blue]")
                cap_str = "  " + " ".join(caps)

            c_node.add(f"[italic]{e.action}[/italic]  ({status}){cap_str}")

    console.print(root)
    console.print("")


def get_endpoints(
    analyzer: Analyzer, language: str | None = None, depth: int = 10
) -> list[Endpoint]:
    """
    Identifies web endpoints and their authentication status using robust CFG analysis.
    """
    lang = language.lower() if language else None
    ruleset = getattr(rules, lang, None) if lang else None

    # 1. Find all candidate controller methods
    controller_pattern = ruleset.Controller() if ruleset else rules.Controller()
    endpoints_matches = analyzer.execute(Query.source(controller_pattern).summary()).value_or([])

    # 2. Identify which of these are "Protected"
    barrier = ruleset.AuthBarrier() if ruleset else rules.AuthBarrier()
    bypass = ruleset.AuthBypass() if ruleset else rules.AuthBypass()

    # A method is protected if it's guarded by a barrier.
    # Our improved Method pattern also checks class-level annotations.
    protected_query = Query.source(
        Return().inside(controller_pattern).is_dominated_by(barrier)
    ).summary()
    protected_matches = analyzer.execute(protected_query).value_or([])
    protected_sigs = set(m.method_fullname for m in protected_matches)

    if lang == "javascript":
        guarded_query = Query.source(controller_pattern.where(barrier)).summary()
        guarded_matches = analyzer.execute(guarded_query).value_or([])
        protected_sigs.update(m.method_fullname for m in guarded_matches)

    # A method is explicitly EXEMPT if it has an AuthBypass annotation.
    bypass_query = Query.source(controller_pattern.where(bypass)).summary()
    bypass_matches = analyzer.execute(bypass_query).value_or([])
    bypass_sigs = set(m.method_fullname for m in bypass_matches)

    # 3. Identify Capabilities (Side Effects) using Backwards Call Graph Traversal
    capability_regexes = slicing_rules.get_capability_rules(lang or "")

    endpoint_fullnames = [m.method_fullname for m in endpoints_matches]
    capabilities_by_endpoint: dict[str, dict[str, list[str]]] = {
        fn: {} for fn in endpoint_fullnames
    }

    if endpoint_fullnames:
        # We use a robust backwards traversal: Sink -> Caller* -> Endpoint
        # We collect the sink names (evidence) as we go.
        for cap_name, regex in capability_regexes.items():
            esc_regex = _esc(regex)
            scala_query = f"""
            val sinks = cpg.call.filter(c =>
              !c.methodFullName.startsWith("__ecma") &&
              !c.methodFullName.startsWith("__whatwg") &&
              !c.methodFullName.startsWith("<operator>")
            ).methodFullName("(?i).*{esc_regex}.*").l
            if (sinks.isEmpty) {{
                ujson.Obj()
            }} else {{
                val evidenceMapping = scala.collection.mutable.Map[String,
                  scala.collection.mutable.Set[String]]()
                sinks.foreach {{ s =>
                    val rawName = s.methodFullName
                    val sinkDisplay = if (rawName.startsWith("<operator>") ||
                      rawName == "<unknownFullName>") s.name
                    else {{
                        val cleanName = rawName.replace("<unresolvedNamespace>.", "")
                          .replace("<unresolvedSignature>", "")
                        val withoutArgs = cleanName.split("\\\\(").head
                        val parts = withoutArgs.split("[:\\\\.]")
                          .filter(p => p.nonEmpty && p != "<returnValue>")
                        if (parts.length >= 2) {{
                           var mName = parts.last
                           val cName = parts(parts.length - 2)
                           if (mName == "<init>" || mName == "__init__" || mName == ".ctor") cName
                           else if (mName == "<member>" || mName == "<unknownFullName>")
                             s"$cName.${{s.name}}"
                           else s"$cName.$mName"
                        }} else if (withoutArgs.contains("<member>") ||
                          withoutArgs.contains("<unknownFullName>")) s.name
                        else withoutArgs
                    }}

                    s.method.foreach {{ sm =>
                        val callers = cpg.method.id(sm.id).repeat(m =>
                            m.callIn.method ++ cpg.call.methodFullName(
                              java.util.regex.Pattern.quote(m.property("FULL_NAME").toString)
                            ).method
                        )(_.emit.maxDepth({depth})).l
                        callers.foreach {{ c =>
                            val fn = getMethodFullName(c)
                            evidenceMapping.getOrElseUpdate(fn,
                              scala.collection.mutable.Set[String]()) += sinkDisplay
                        }}
                    }}
                }}
                ujson.Obj.from(evidenceMapping.map {{
                  case (k, v) => k -> ujson.Arr(v.toSeq.map(x => x: ujson.Value)*)
                }}.toMap)
            }}
            """
            result = analyzer.raw_scala(scala_query, prelude=analyzer.session.prelude).bind(
                analyzer.session._parse_json_result
            )
            mapping = result.value_or({})
            if isinstance(mapping, dict):
                for fn, evidence in mapping.items():
                    if fn in capabilities_by_endpoint:
                        capabilities_by_endpoint[fn][cap_name] = sorted(list(set(evidence)))

    endpoints = []
    seen_actions = set()

    def _controller_from_fullname(fullname: str, fallback_file: str) -> str:
        parts = [seg for seg in fullname.split(":") if seg]
        if len(parts) >= 2:
            return parts[-2]
        if fallback_file:
            return fallback_file.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].split(".")[0]
        return "<unknown>"

    for m in sorted(endpoints_matches, key=lambda x: x.method_fullname):
        fullname = m.method_fullname
        if any(x in fullname for x in [".ctor", "get_", "set_", "<lambda>", "<init>", "__init__"]):
            continue

        controller = m.class_name
        if lang == "javascript" and controller == "<unknown>":
            controller = _controller_from_fullname(m.method_fullname, m.file)
        action = m.method_name

        if (controller, action) in seen_actions:
            continue
        seen_actions.add((controller, action))

        # It's protected if it matched the protected query AND it's not explicitly bypassed
        is_authed = (fullname in protected_sigs) and (fullname not in bypass_sigs)
        endpoints.append(
            Endpoint(
                controller=controller,
                action=action,
                fullname=fullname,
                is_protected=is_authed,
                capabilities=capabilities_by_endpoint.get(fullname, {}),
            )
        )

    return endpoints


def run_scans(
    analyzer: Analyzer,
    scans: list[ScanRule],
    reporters: list[Reporter],
    status_callback=None,
    severity_min: Severity | None = None,
):
    """
    Orchestrates the execution of multiple scan rules and reports results.
    """
    for rule in scans:
        if severity_min and rule.severity < severity_min:
            continue
        if status_callback:
            status_callback(f"Scanning for {rule.name}...")

        results = analyzer.execute(rule.query).unwrap()

        if results:
            for reporter in reporters:
                reporter.report(rule, results)

    for reporter in reporters:
        if hasattr(reporter, "finalize"):
            reporter.finalize()
