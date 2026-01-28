import os
from dataclasses import dataclass, field

from rich.console import Console
from rich.tree import Tree

from . import rules
from .analyzer import Analyzer
from .core.rule import Confidence, ScanRule, Severity
from .dsl.patterns import _esc
from .dsl.query import Query
from .reporting import Reporter

FRONTEND_ENDPOINT_HINTS = [
    "/frontend/",
    "/client/",
    "/ui/",
    "/web/",
    "/public/",
    "/static/",
    "/assets/",
    "/components/",
    "/views/",
]
BACKEND_ENDPOINT_HINTS = [
    "/backend/",
    "/server/",
    "/api/",
    "/routes/",
    "/routers/",
    "/controllers/",
]


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
        if "::program" in controller:
            display_name = controller.split("::program")[0].split("/")[-1].split("\\")[-1]
        elif ":" in controller:
            display_name = controller.split(":")[-1]
        elif "/" in controller:
            display_name = controller.split("/")[-1]
        elif "\\" in controller:
            display_name = controller.split("\\")[-1]
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

    def is_frontend_endpoint(path: str) -> bool:
        if not path:
            return False
        norm = path.replace("\\", "/").lower()
        if any(hint in norm for hint in BACKEND_ENDPOINT_HINTS):
            return False
        return any(hint in norm for hint in FRONTEND_ENDPOINT_HINTS)

    # 1. Find all candidate controller methods
    controller_pattern = ruleset.Controller() if ruleset else rules.Controller()
    endpoints_matches = analyzer.execute(Query.source(controller_pattern).summary()).value_or([])
    if lang == "javascript":
        endpoints_matches = [
            m
            for m in endpoints_matches
            if not is_frontend_endpoint(m.file or m.method_fullname.split(":")[0])
        ]

    # 2. Identify which of these are "Protected"
    barrier_pattern = ruleset.AuthBarrier() if ruleset else rules.AuthBarrier()
    bypass_pattern = ruleset.AuthBypass() if ruleset else rules.AuthBypass()

    barrier_pred = barrier_pattern.to_cpg_predicate()

    barrier_heuristics = rules.get_barrier_heuristics(language)
    import json

    barriers_json = json.dumps(
        [{"category": h.category, "patterns": h.patterns} for h in (barrier_heuristics or [])]
    )

    # Improved Scala query to find endpoints and their specific guards
    endpoint_fullnames = [m.method_fullname for m in endpoints_matches]
    methods_json = json.dumps(endpoint_fullnames)

    # Identify explicit EXEMPT if it has an AuthBypass annotation.
    bypass_query = Query.source(controller_pattern.where(bypass_pattern)).summary()
    bypass_matches = analyzer.execute(bypass_query).value_or([])
    if lang == "javascript":
        bypass_matches = [
            m
            for m in bypass_matches
            if not is_frontend_endpoint(m.file or m.method_fullname.split(":")[0])
        ]
    bypass_sigs = set(m.method_fullname for m in bypass_matches)

    guard_mapping = {}
    path_mapping = {}
    debug_routes = os.getenv("HOPPY_DEBUG_ROUTES") == "1"
    if endpoint_fullnames:
        scala_guards = f"""
        import io.shiftleft.codepropertygraph.generated.nodes
        import io.shiftleft.semanticcpg.language._
        import ujson._

        val startMethodsList = ujson.read(\"\"\"{methods_json}\"\"\").arr.map(_.str).l
        val barrierHeuristics = ujson.read(\"\"\"{barriers_json}\"\"\").arr
        val isAuthBarrier = {barrier_pred}

        def getBarriers(m: nodes.Method): List[String] = {{
          val fromAnnotation = (m.start.annotation ++ m.typeDecl.annotation).filter {{ a =>
            barrierHeuristics.exists(_.obj("patterns").arr.map(_.str).exists(p =>
              a.name.matches(p)))
          }}.code.l

          val fromCalls = m.call.filter {{ c =>
            barrierHeuristics.exists(_.obj("patterns").arr.map(_.str).exists(p =>
              c.methodFullName.matches(p) || c.name.matches(p)))
          }}.code.l

          if (isAuthBarrier(m) || fromAnnotation.nonEmpty || fromCalls.nonEmpty) {{
            (fromAnnotation ++ fromCalls).distinct
          }} else if (m.name.toLowerCase.matches(
            ".*(auth|login|verify|perm|authorize|secure).*"
          )) {{
            List(m.name)
          }} else {{
            List.empty
          }}
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

        def resolveCode(node: nodes.Expression): String = {{
          node match {{
            case call: nodes.Call if call.name == "<operator>.formatString" =>
              call.astChildren.collectAll[nodes.Expression].map(resolveCode).mkString("")
            case call: nodes.Call if (call.name == "<operator>.addition" ||
                                      call.name == "<operator>.plus") =>
              call.argument.l.sortBy(_.order).map(resolveCode).mkString("")
            case call: nodes.Call if call.name == "<operator>.fieldAccess" =>
              val field = call.astChildren.collectAll[nodes.FieldIdentifier]
                .code.headOption.getOrElse(call.code)
              s"{{${{field}}}}"
            case lit: nodes.Literal =>
              lit.code.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'")
            case id: nodes.Identifier => s"{{${{id.name}}}}"
            case _ => node.code
          }}
        }}

        def resolvePathOpt(node: nodes.Expression): Option[String] = {{
          node match {{
            case call: nodes.Call if call.name == "<operator>.formatString" =>
              Some(call.astChildren.collectAll[nodes.Expression].map(resolveCode).mkString(""))
            case call: nodes.Call if (call.name == "<operator>.addition" ||
                                      call.name == "<operator>.plus") =>
              Some(call.argument.l.sortBy(_.order).map(resolveCode).mkString(""))
            case call: nodes.Call if call.name == "<operator>.fieldAccess" =>
              val field = call.astChildren.collectAll[nodes.FieldIdentifier]
                .code.headOption.getOrElse(call.code)
              Some(s"{{${{field}}}}")
            case lit: nodes.Literal =>
              Some(lit.code.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'"))
            case _ => None
          }}
        }}

        def stripQuotes(value: String): String = {{
          value
            .stripPrefix("\"")
            .stripSuffix("\"")
            .stripPrefix("'")
            .stripSuffix("'")
            .replace("\\\"", "")
            .replace("'", "")
        }}

        def joinPath(prefix: String, route: String): String = {{
          val cleanedPrefix = stripQuotes(prefix)
          val cleanedRoute = stripQuotes(route)
          val p = if (cleanedPrefix.endsWith("/")) cleanedPrefix.dropRight(1) else cleanedPrefix
          val r = if (cleanedRoute.startsWith("/")) cleanedRoute else s"/${{cleanedRoute}}"
          if (p.isEmpty) r else s"${{p}}${{r}}"
        }}

        def normalizeModulePath(raw: String): String = {{
          stripQuotes(raw).stripPrefix("./")
        }}

        def moduleFromType(typeFullName: String): String = {{
          val parts = typeFullName.split(":")
          if (parts.nonEmpty) parts.head else ""
        }}

        def versionSuffix(name: String): Option[String] = {{
          val r = "(?i).*v(\\\\d+)$".r
          name match {{
            case r(ver) => Some(ver)
            case _ => None
          }}
        }}

        def resolveAssignedExprs(id: nodes.Identifier): List[nodes.Expression] = {{
          id.out("REF").collectAll[nodes.Local].in("REF").collectAll[nodes.Identifier]
            .inCall.name("<operator>.assignment").argument(2).collectAll[nodes.Expression].l
        }}

        def resolveMountKeys(expr: nodes.Expression): List[String] = {{
          expr match {{
            case id: nodes.Identifier =>
              val assigned = resolveAssignedExprs(id).flatMap(resolveMountKeys)
              (List(id.name) ++ assigned).distinct
            case call: nodes.Call if call.name == "require" =>
              List(normalizeModulePath(call.argument(1).code))
            case call: nodes.Call if call.name == "<operator>.fieldAccess" =>
              val field = call.argument(2).code
              call.argument(1) match {{
                case recvId: nodes.Identifier =>
                  val module = moduleFromType(recvId.typeFullName)
                  val recvKeys = resolveMountKeys(recvId)
                  val baseKeys = if (field == "default") recvKeys else (List(field) ++ recvKeys)
                  val derived = versionSuffix(field)
                    .orElse(versionSuffix(recvId.name))
                    .filter(_ => module.nonEmpty)
                    .map(ver => s"${{module}}/v${{ver}}")
                    .toList
                  (baseKeys ++ (if (module.nonEmpty) List(module) else List.empty) ++
                   derived).distinct
                case recvCall: nodes.Call if recvCall.name == "require" =>
                  val modPath = normalizeModulePath(recvCall.argument(1).code)
                  val baseKeys = if (field == "default") List(modPath) else List(field, modPath)
                  val derived = versionSuffix(field).map(ver => s"${{modPath}}/v${{ver}}").toList
                  (baseKeys ++ derived).distinct
                case _ => List(field)
              }}
            case _ => List.empty
          }}
        }}

        def fileMatchesKey(name: String, fileName: String): Boolean = {{
          val key = name.stripPrefix("./")
          val direct =
            fileName.endsWith(s"/${{key}}.ts") ||
            fileName.endsWith(s"/${{key}}.js") ||
            fileName.endsWith(s"/${{key}}/index.ts") ||
            fileName.endsWith(s"/${{key}}/index.js") ||
            fileName.contains(s"/${{key}}/") ||
            fileName.endsWith(s"${{key}}.ts") ||
            fileName.endsWith(s"${{key}}.js") ||
            fileName.endsWith(s"${{key}}/index.ts") ||
            fileName.endsWith(s"${{key}}/index.js") ||
            fileName.contains(s"${{key}}/")
          val versionMatch = versionSuffix(key).exists {{ ver =>
            fileName.contains(s"/v${{ver}}/") ||
            fileName.endsWith(s"/v${{ver}}/index.ts") ||
            fileName.endsWith(s"/v${{ver}}/index.js") ||
            fileName.contains(s"v${{ver}}/")
          }}
          direct || versionMatch
        }}

        def prefixesForFile(
          fileName: String, mounts: Map[String, List[String]]
        ): List[String] = {{
          mounts.collect {{
            case (name, prefix) if fileMatchesKey(name, fileName) => prefix
          }}.toList.flatten.distinct
        }}

        def pathIndex(args: List[nodes.Expression]): Int = {{
          args.indexWhere(a => resolvePathOpt(a).isDefined)
        }}

        def resolveMethodRefs(node: nodes.Expression): List[String] = {{
          val direct = node match {{
            case m: nodes.MethodRef => List(m.methodFullName)
            case id: nodes.Identifier =>
              val lambdaRefs = if (id.name.matches("<lambda>\\\\d+")) {{
                cpg.method.nameExact(id.name).fullName.l
              }} else List.empty
              id.out("REF").collectAll[nodes.Local].in("REF").collectAll[nodes.Identifier]
                .inCall.name("<operator>.assignment").argument(2).isMethodRef.methodFullName.l
                .++(lambdaRefs)
            case lit: nodes.Literal =>
              val name = stripQuotes(lit.code)
              if (name.matches("<lambda>\\\\d+")) cpg.method.nameExact(name).fullName.l
              else List.empty
            case call: nodes.Call =>
              val fromName = if (call.methodFullName == "<unknownFullName>") {{
                cpg.method.nameExact(call.name).flatMap(m =>
                  (List(m.fullName) ++ m.ast.collectAll[nodes.Method].fullName.l).distinct
                ).l
              }} else List.empty
              val method = cpg.method.fullNameExact(call.methodFullName)
              val fromMethodRef = method.ast.isReturn.astChildren.isMethodRef.methodFullName.l
              val fromMethod = method.ast.isReturn.astChildren.collectAll[nodes.Method].fullName.l
              val nestedMethods = method.ast.collectAll[nodes.Method].fullName.l
              (fromName ++ fromMethodRef ++ fromMethod ++ nestedMethods).distinct
            case _ => List.empty
          }}
          val astRefs = node.ast.collectAll[nodes.MethodRef].methodFullName.l
          val astMethods = node.ast.collectAll[nodes.Method].fullName.l
          (direct ++ astRefs ++ astMethods).distinct
        }}

        val directRouteInfo = cpg.call
          .name("get|post|put|delete|patch|all|use")
          .flatMap {{ c =>
           val orderedArgs = c.argument.l.sortBy(_.order)
           val receiverName = orderedArgs.headOption.collect {{
             case id: nodes.Identifier => id.name
           }}.getOrElse("")
           if (receiverName != "app") List.empty
           else {{
             val pIndex = pathIndex(orderedArgs)
             val afterPath = if (pIndex >= 0) orderedArgs.drop(pIndex + 1) else orderedArgs
             val argMethodRefs = afterPath.flatMap(resolveMethodRefs)
             val handler = argMethodRefs.find(_.contains("<lambda>"))
               .orElse(argMethodRefs.lastOption)
             val middlewares = if (argMethodRefs.length > 1) {{
               argMethodRefs.dropRight(1)
             }} else List.empty

             val guardMatches = middlewares.flatMap {{ mName =>
               cpg.method.fullNameExact(mName).headOption match {{
                 case Some(m) => getBarriers(m)
                 case None =>
                   val matchesHeuristic = barrierHeuristics.exists(_.obj("patterns")
                    .arr.map(_.str).exists(p => mName.matches(p)))
                   if (matchesHeuristic) List(mName) else List.empty
               }}
             }}.distinct

             val pathVal = pIndex match {{
               case i if i >= 0 => resolveCode(orderedArgs(i))
               case _ => ""
             }}
             val pathStr = s"${{c.name.toUpperCase}} ${{pathVal}}"

             val handlerTargets = handler.toList.flatMap {{ h =>
               if (h.contains("<lambda>")) List(h)
               else {{
                 val lambdas = cpg.method.fullNameExact(h).ast.collectAll[nodes.Method].fullName.l
                   .filter(_.contains("<lambda>"))
                 if (lambdas.nonEmpty) lambdas else List(h)
               }}
             }}

             handlerTargets.map(h => ujson.Obj(
               "handler" -> ujson.Str(h),
               "path" -> ujson.Str(pathStr),
               "guards" -> ujson.Arr(guardMatches.map(ujson.Str(_))*)
             ))
           }}
        }}.l

        val baseRouterMounts = cpg.call
          .name("use")
          .flatMap {{ c =>
          val orderedArgs = c.argument.l.sortBy(_.order)
          val receiverName = orderedArgs.headOption.collect {{
            case id: nodes.Identifier => id.name
          }}.getOrElse("")
          if (receiverName != "app") List.empty
          else {{
          val pIndex = pathIndex(orderedArgs)
          val path = if (pIndex >= 0) resolvePathOpt(orderedArgs(pIndex)) else None
          val afterPath = if (pIndex >= 0) orderedArgs.drop(pIndex + 1) else orderedArgs
          val routerExpr = afterPath.lastOption
          val routerKeys = routerExpr.toList.flatMap(resolveMountKeys)
          (path, routerKeys.headOption) match {{
            case (Some(p), Some(_)) => routerKeys.distinct.map(r => r -> p)
            case _ => List.empty
          }}
          }}
        }}.groupBy(_._1).view.mapValues(_.map(_._2).distinct).toMap

        def addNestedMounts(mounts: Map[String, List[String]]): Map[String, List[String]] = {{
          val nested = cpg.call.name("use").flatMap {{ c =>
            val orderedArgs = c.argument.l.sortBy(_.order)
            val receiverName = orderedArgs.headOption.collect {{
              case id: nodes.Identifier => id.name
            }}.getOrElse("")
            if (receiverName == "app") List.empty
            else {{
              val fileName = c.file.name.headOption.getOrElse("")
              val parentPrefixes = prefixesForFile(fileName, mounts)
              val pIndex = pathIndex(orderedArgs)
              val pathOpt = if (pIndex >= 0) resolvePathOpt(orderedArgs(pIndex)) else None
              val afterPath = if (pIndex >= 0) orderedArgs.drop(pIndex + 1) else orderedArgs
              val routerExpr = afterPath.lastOption
              val routerKeys = routerExpr.toList.flatMap(resolveMountKeys).distinct
              (parentPrefixes, pathOpt) match {{
                case (prefixes, Some(route)) if prefixes.nonEmpty && routerKeys.nonEmpty =>
                  for {{
                    key <- routerKeys
                    prefix <- prefixes
                  }} yield key -> joinPath(prefix, route)
                case _ => List.empty
              }}
            }}
          }}.l
          val merged = mounts.toSeq ++ nested.map {{ case (k, v) => k -> List(v) }}
          merged.groupBy(_._1).view.mapValues(_.flatMap(_._2).distinct.toList).toMap
        }}

        var routerMounts = baseRouterMounts
        for (_ <- 0 until 3) {{
          routerMounts = addNestedMounts(routerMounts)
        }}

        val routerRouteInfo = cpg.call.name("get|post|put|delete|patch|all|use").flatMap {{ c =>
          val orderedArgs = c.argument.l.sortBy(_.order)
          val receiverName = orderedArgs.headOption.collect {{
            case id: nodes.Identifier => id.name
          }}.getOrElse("")
          val fileName = c.file.name.headOption.getOrElse("")
          val filePrefixes = prefixesForFile(fileName, routerMounts)
          val prefixes = (routerMounts.getOrElse(receiverName, Nil) ++ filePrefixes).distinct
          if (prefixes.isEmpty) List.empty
          else {{
            val pIndex = pathIndex(orderedArgs)
            val pathOpt = if (pIndex >= 0) resolvePathOpt(orderedArgs(pIndex)) else None
            pathOpt.toList.flatMap {{ route =>
              val fullPaths = prefixes.map(p => s"${{c.name.toUpperCase}} ${{joinPath(p, route)}}")
              val afterPath = if (pIndex >= 0) orderedArgs.drop(pIndex + 1) else orderedArgs
              val argMethodRefs = afterPath.flatMap(resolveMethodRefs)
              val handler = argMethodRefs.find(_.contains("<lambda>"))
                .orElse(argMethodRefs.lastOption)
              val middlewares = if (argMethodRefs.length > 1) {{
                argMethodRefs.dropRight(1)
              }} else List.empty

              val guardMatches = middlewares.flatMap {{ mName =>
                cpg.method.fullNameExact(mName).headOption match {{
                  case Some(m) => getBarriers(m)
                  case None =>
                    val matchesHeuristic = barrierHeuristics.exists(_.obj("patterns")
                      .arr.map(_.str).exists(p => mName.matches(p)))
                    if (matchesHeuristic) List(mName) else List.empty
                }}
              }}.distinct

              val handlerTargets = handler.toList.flatMap {{ h =>
                if (h.contains("<lambda>")) List(h)
                else {{
                  val lambdas = cpg.method.fullNameExact(h).ast.collectAll[nodes.Method].fullName.l
                    .filter(_.contains("<lambda>"))
                  if (lambdas.nonEmpty) lambdas else List(h)
                }}
              }}

              handlerTargets.flatMap {{ h =>
                fullPaths.map(p => ujson.Obj(
                  "handler" -> ujson.Str(h),
                  "path" -> ujson.Str(p),
                  "guards" -> ujson.Arr(guardMatches.map(ujson.Str(_))*)
                ))
              }}
            }}
          }}
        }}.l

        val routeInfo = directRouteInfo ++ routerRouteInfo
        val paths = routeInfo
          .groupBy(r => r.obj("handler").str)
          .view
          .mapValues(rs => rs.map(_.obj("path").str).maxBy(_.length))
          .toMap
        val routeGuards = routeInfo.map(r => r.obj("handler").str -> r.obj("guards")).toMap

        val mergedGuards = (mapping.toSeq ++ routeGuards.toSeq).groupBy(_._1).map {{
          case (k, vals) =>
            val guards = vals.flatMap {{ case (_, v) => v.arr.map(_.str) }}.distinct
            k -> ujson.Arr(guards.map(ujson.Str(_))*)
        }}.toMap

        {
            ""
            if not debug_routes
            else '''
        val debug = ujson.Obj(
          "direct_routes" -> ujson.Num(directRouteInfo.size),
          "router_routes" -> ujson.Num(routerRouteInfo.size),
          "router_mounts" -> ujson.Num(routerMounts.size),
          "sample_paths" -> ujson.Arr(
            directRouteInfo.take(5).map(r => ujson.Str(r.obj("path").str))*
          ),
          "router_mount_samples" -> ujson.Obj.from(
            routerMounts.take(3).map {{ case (k, v) => k -> ujson.Arr(v.map(ujson.Str(_))* ) }}
          )
        )
        '''
        }
        ujson.Obj(
          "guards" -> ujson.Obj.from(mergedGuards),
          "paths" -> ujson.Obj.from(paths.map {{ case (k, v) => k -> ujson.Str(v) }})
          {"" if not debug_routes else ', "debug" -> debug'}
        )
        """
        if debug_routes:
            print("[debug] route mapping scala snippet (head):")
            print(scala_guards[:400].rstrip())
            print("[debug] route mapping scala snippet (tail):")
            print(scala_guards[-400:].rstrip())
        scala_result = analyzer.raw_scala(scala_guards, prelude=analyzer.session.prelude)
        if debug_routes and scala_result:
            raw_output = scala_result.unwrap()
            print("[debug] route mapping raw output:")
            print(raw_output[:800].rstrip())
        if debug_routes and not scala_result:
            print(f"[debug] route mapping scala failed: {scala_result.failure()}")
        result = scala_result.bind(analyzer.session._parse_json_result)
        if debug_routes and not result:
            print(f"[debug] route mapping parse failed: {result.failure()}")
        combined_res = result.value_or({})
        guard_mapping = combined_res.get("guards", {})
        path_mapping = combined_res.get("paths", {})
        if debug_routes:
            debug_info = combined_res.get("debug", {})
            if debug_info:
                print(f"[debug] route mapping: {debug_info}")
            else:
                print(
                    "[debug] route mapping empty",
                    f"guards={len(guard_mapping)}",
                    f"paths={len(path_mapping)}",
                )
            for key, value in path_mapping.items():
                if "dataErasure" in key:
                    print(f"[debug] dataErasure path: {key} -> {value}")

    # 3. Identify Capabilities (Side Effects) using forward traversal from endpoints
    capability_heuristics = rules.get_discovery_heuristics(lang or "")

    endpoint_fullnames = [m.method_fullname for m in endpoints_matches]
    capabilities_by_endpoint: dict[str, dict[str, list[str]]] = {
        fn: {} for fn in endpoint_fullnames
    }

    if endpoint_fullnames and capability_heuristics:
        caps_json = json.dumps(
            [
                {"name": h.category, "pattern": _esc(pat)}
                for h in capability_heuristics
                for pat in h.patterns
            ]
        )
        scala_query = f"""
        import io.shiftleft.codepropertygraph.generated.nodes
        import io.shiftleft.semanticcpg.language._
        import ujson._

        val startMethodsList = ujson.read(\"\"\"{methods_json}\"\"\").arr.map(_.str).l
        val caps = ujson.read(\"\"\"{caps_json}\"\"\").arr

        def isInterestingCall(c: nodes.Call): Boolean =
          !c.methodFullName.startsWith("__ecma") &&
          !c.methodFullName.startsWith("__whatwg") &&
          !c.methodFullName.startsWith("<operator>")

        def sinkDisplay(c: nodes.Call): String = {{
          val rawName = c.methodFullName
          if (rawName.startsWith("<operator>") || rawName == "<unknownFullName>") c.name
          else {{
            val cleanName = rawName.replace("<unresolvedNamespace>.", "")
              .replace("<unresolvedSignature>", "")
            val withoutArgs = cleanName.split("\\\\(").head
            val parts = withoutArgs.split("[:\\\\.]")
              .filter(p => p.nonEmpty && p != "<returnValue>")
            if (parts.length >= 2) {{
              val mName = parts.last
              val cName = parts(parts.length - 2)
              if (mName == "<init>" || mName == "__init__" || mName == ".ctor") cName
              else if (mName == "<member>" || mName == "<unknownFullName>")
                s"$cName.${{c.name}}"
              else s"$cName.$mName"
            }} else if (withoutArgs.contains("<member>") ||
              withoutArgs.contains("<unknownFullName>")) c.name
            else withoutArgs
          }}
        }}

        val methodSet = cpg.method.fullName.l.toSet
        def normalize(s: String): String = s.replaceAll("\\\\s+", " ").trim

        case class CallInfo(
          caller: String,
          callee: String,
          display: String,
          name: String,
          code: String,
          codeNorm: String
        )

        val callTuples = cpg.call.filter(isInterestingCall).l.map {{ c =>
          CallInfo(
            c.method.fullName,
            c.methodFullName,
            sinkDisplay(c),
            c.name,
            c.code,
            normalize(c.code)
          )
        }}

        val callsByMethod = callTuples.groupBy(_.caller)
        val adjacency = callTuples.flatMap {{ c =>
          if (methodSet.contains(c.caller) && methodSet.contains(c.callee)) {{
            Some(c.caller -> c.callee)
          }} else None
        }}.groupBy(_._1).view.mapValues(_.map(_._2).distinct).toMap

        val nestedByMethod = cpg.method.flatMap {{ m =>
          m.ast.isMethod
            .filter(l => l.fullName != m.fullName && l.name.contains("<lambda>"))
            .map(l => m.fullName -> l.fullName).l
        }}.groupBy(_._1).view.mapValues(_.map(_._2).distinct).toMap

        val reachCache = scala.collection.mutable.Map[String, Set[String]]()
        def reachable(start: String): Set[String] = {{
          reachCache.getOrElseUpdate(start, {{
            val visited = scala.collection.mutable.Set[String](start)
            val queue = scala.collection.mutable.Queue[(String, Int)]((start, 0))
            while (queue.nonEmpty) {{
              val (cur, d) = queue.dequeue()
              if (d < {depth}) {{
                val nexts = adjacency.getOrElse(cur, Nil) ++
                            nestedByMethod.getOrElse(cur, Nil)
                nexts.foreach {{ next =>
                  if (!visited.contains(next)) {{
                    visited += next
                    queue.enqueue((next, d + 1))
                  }}
                }}
              }}
            }}
            visited.toSet
          }})
        }}

        val mapping = startMethodsList.flatMap {{ mName =>
          if (!methodSet.contains(mName)) List.empty
          else {{
            val methods = reachable(mName)
            val calls = methods.flatMap(m => callsByMethod.getOrElse(m, Nil)).toList

            val capObj = scala.collection.mutable.Map[String, ujson.Value]()
            caps.foreach {{ cap =>
              val name = cap.obj("name").str
              val pattern = cap.obj("pattern").str
              val re = s"(?s)${{pattern}}"
              val evidence = calls
                .filter(c =>
                  List(c.caller, c.callee, c.display, c.name, c.codeNorm)
                    .exists(_.matches(re))
                )
                .map(_.display)
                .distinct
              if (evidence.nonEmpty) {{
                capObj(name) = ujson.Arr(evidence.map(ujson.Str(_))*)
              }}
            }}

            if (capObj.nonEmpty) List(mName -> ujson.Obj.from(capObj)) else List.empty
          }}
        }}.toMap

        ujson.Obj.from(mapping)
        """
        debug_caps = os.getenv("HOPPY_DEBUG_CAPS") == "1"
        result = analyzer.raw_scala(scala_query, prelude=analyzer.session.prelude).bind(
            analyzer.session._parse_json_result
        )
        if debug_caps and not result:
            print(f"[debug] capabilities scala failed: {result.failure()}")
        mapping = result.value_or({})
        if isinstance(mapping, dict):
            for fn, caps in mapping.items():
                if fn in capabilities_by_endpoint and isinstance(caps, dict):
                    capabilities_by_endpoint[fn] = {
                        cap: sorted(list(set(evidence)))
                        for cap, evidence in caps.items()
                        if isinstance(evidence, list)
                    }
        if debug_caps:
            matched = sum(1 for v in capabilities_by_endpoint.values() if v)
            print(
                "[debug] capabilities:",
                f"heuristics={len(capability_heuristics)}",
                f"endpoints={len(endpoint_fullnames)}",
                f"matched={matched}",
                f"mapping={len(mapping) if isinstance(mapping, dict) else 'n/a'}",
            )

    endpoints = []
    seen_actions = set()

    def _controller_from_fullname(fullname: str, fallback_file: str) -> str:
        parts = [seg for seg in fullname.split(":") if seg]
        # For JS/TS, 'program' is a generic top-level name we want to skip
        if len(parts) >= 2:
            name = parts[-2]
            if name == "program" and len(parts) >= 3:
                # If we have file.ts::program:<lambda>, use file.ts
                return parts[-3].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if name == "program":
                return parts[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            return name
        if fallback_file:
            return fallback_file.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].split(".")[0]
        return "<unknown>"

    for m in sorted(endpoints_matches, key=lambda x: x.method_fullname):
        fullname = m.method_fullname
        if any(x in fullname for x in [".ctor", "get_", "set_", "<init>", "__init__"]):
            continue

        controller = m.class_name
        if lang == "javascript" and controller == "<unknown>":
            controller = _controller_from_fullname(m.method_fullname, m.file)

        action = m.method_name
        action = path_mapping.get(fullname, action)
        if action.startswith("<lambda>") and m.line:
            action = f"{action} (L{m.line})"

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
