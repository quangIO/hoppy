from dataclasses import dataclass, field

from rich.console import Console
from rich.tree import Tree

from . import rules, slicing_rules
from .analyzer import Analyzer
from .core.rule import Confidence, ScanRule, Severity
from .dsl.patterns import Return, _esc
from .dsl.query import Query
from .reporting import Reporter


@dataclass
class Endpoint:
    controller: str
    action: str
    fullname: str
    is_protected: bool
    guards: list[str] = field(default_factory=list)
    capabilities: dict[str, list[str]] = field(default_factory=dict)


def display_endpoints(endpoints: list[Endpoint], console: Console | None = None):
    """
    Displays a tree of endpoints and their authentication status.
    """
    import re
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
            if e.is_protected:
                if e.guards:
                    cleaned = []
                    for b in e.guards:
                        c = re.sub(r"\s+", " ", b).strip()
                        if len(c) > 60:
                            c = c[:57] + "..."
                        cleaned.append(c)
                    guard_str = ", ".join(cleaned)
                    status = f"[bold green]Guarded: {guard_str}[/bold green]"
                else:
                    status = "[bold green]Protected?[/bold green]"
            else:
                status = "[bold yellow]PUBLIC?[/bold yellow]"

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

            c_node.add(f"[italic]{e.action}[/italic]  ([{status}]){cap_str}")

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
    barrier_pattern = ruleset.AuthBarrier() if ruleset else rules.AuthBarrier()
    bypass_pattern = ruleset.AuthBypass() if ruleset else rules.AuthBypass()
    
    barrier_pred = barrier_pattern.to_cpg_predicate()
    
    barrier_heuristics = rules.get_barrier_heuristics(language)
    import json
    barriers_json = json.dumps([{"category": h.category, "patterns": h.patterns} for h in (barrier_heuristics or [])])

    # Improved Scala query to find endpoints and their specific guards
    endpoint_fullnames = [m.method_fullname for m in endpoints_matches]
    methods_json = json.dumps(endpoint_fullnames)
    
    # Identify explicit EXEMPT if it has an AuthBypass annotation.
    bypass_query = Query.source(controller_pattern.where(bypass_pattern)).summary()
    bypass_matches = analyzer.execute(bypass_query).value_or([])
    bypass_sigs = set(m.method_fullname for m in bypass_matches)

    guard_mapping = {}
    if endpoint_fullnames:
        scala_guards = f"""
        import io.shiftleft.codepropertygraph.generated.nodes
        import io.shiftleft.semanticcpg.language._
        import ujson._

        val startMethodsList = ujson.read(\"\"\"{methods_json}\"\"\").arr.map(_.str).l
        val barrierHeuristics = ujson.read(\"\"\"{barriers_json}\"\"\").arr
        val isAuthBarrier = {barrier_pred}

        def getBarriers(m: nodes.Method): List[String] = {{
          if (isAuthBarrier(m)) {{
             val fromAnnotation = (m.start.annotation ++ m.typeDecl.annotation).filter(a => 
                barrierHeuristics.exists(_.obj("patterns").arr.map(_.str).exists(p => a.name.matches(p)))
             ).code.l

             val fromCalls = m.call.filter(c => 
                barrierHeuristics.exists(_.obj("patterns").arr.map(_.str).exists(p => c.methodFullName.matches(p) || c.name.matches(p)))
             ).code.l
             
             if (fromAnnotation.nonEmpty || fromCalls.nonEmpty) {{
                (fromAnnotation ++ fromCalls).distinct
             }} else if (m.name.toLowerCase.matches(".*(auth|login|verify|perm|authorize|secure).*")) {{
                List(m.name)
             }} else {{
                List.empty
             }}
          }} else List.empty
        }}

        val mapping = startMethodsList.flatMap {{ mName =>
          cpg.method.fullNameExact(mName).map {{ m =>
             val directGuards = getBarriers(m)
             val dominatedGuards = if (directGuards.isEmpty) {{
                // Check if the method is dominated by a barrier in the CFG
                m.start.isReturn.dominatedBy.collectAll[nodes.CfgNode].filter(isAuthBarrier).code.l
             }} else List.empty
             
             mName -> ujson.Arr((directGuards ++ dominatedGuards).distinct.map(ujson.Str(_))*)
          }}
        }}.toMap

        ujson.Obj.from(mapping)
        """
        result = analyzer.raw_scala(scala_guards, prelude=analyzer.session.prelude).bind(
            analyzer.session._parse_json_result
        )
        guard_mapping = result.value_or({})

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

        # It's protected if it has guards and it's not explicitly bypassed
        guards = guard_mapping.get(fullname, [])
        is_authed = (len(guards) > 0) and (fullname not in bypass_sigs)
        
        endpoints.append(
            Endpoint(
                controller=controller,
                action=action,
                fullname=fullname,
                is_protected=is_authed,
                guards=guards,
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
    confidence_min: Confidence | None = None,
):
    """
    Orchestrates the execution of multiple scan rules and reports results.
    """
    for rule in scans:
        if severity_min and rule.severity < severity_min:
            continue
        if confidence_min and rule.confidence < confidence_min:
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
