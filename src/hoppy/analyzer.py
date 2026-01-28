import json
from typing import TYPE_CHECKING, Any, TypeVar, cast

from returns.result import Failure, Result, safe

from .core.manager import JoernSession, JSONValue
from .core.match import Match
from .core.slicing import Slice
from .dsl.query import Query

if TYPE_CHECKING:
    from .rules.discovery import DiscoveryHeuristic

_T = TypeVar("_T")


class Analyzer:
    """
    High-level interface for Joern analysis.
    """

    def __init__(
        self,
        bin_path: str = "joern",
        use_server: bool | None = None,
        server_url: str | None = None,
        port: int | None = None,
        workspace: str | None = None,
        jvm_opts: list[str] | None = None,
        verbose: bool = False,
    ):
        # Backward compatibility logic:
        # If use_server is True or a server_url is provided, we use that explicit server.
        # Otherwise, we spawn an isolated instance (default).
        actual_url = server_url
        if use_server and not actual_url:
            actual_url = "http://localhost:8080"

        self.session = JoernSession(
            bin_path,
            port=port,
            workspace=workspace,
            server_url=actual_url,
            jvm_opts=jvm_opts,
        )
        self._current_cpg: str | None = None
        self.verbose = verbose

    def __enter__(self):
        self.session.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

    def load_code(
        self,
        path: str,
        language: str | None = None,
        joern_parse_args: list[str] | None = None,
        use_cache: bool = True,
    ) -> Result[str, Exception]:
        """Import code into the analysis session."""
        return self.session.import_code(
            path,
            language=language,
            joern_parse_args=joern_parse_args,
            use_cache=use_cache,
        )

    def build_cpg(self, src_path: str, out_path: str):
        """Build a CPG binary from source code using joern-parse."""
        import os
        import subprocess

        # Derive joern-parse path from joern executable (same logic as _import_with_joern_parse)
        joern_parse_cmd = "joern-parse"
        if self.session.bin_path != "joern":
            joern_dir = os.path.dirname(self.session.bin_path)
            joern_parse_path = os.path.join(joern_dir, "joern-parse")
            if os.path.exists(joern_parse_path):
                joern_parse_cmd = joern_parse_path

        import tempfile

        with tempfile.TemporaryFile() as tmp:
            try:
                subprocess.run(
                    [joern_parse_cmd, src_path, "--output", out_path],
                    stdout=tmp,
                    stderr=subprocess.STDOUT,
                    check=True,
                )
            except subprocess.CalledProcessError:
                tmp.seek(0)
                error_msg = tmp.read().decode("utf-8", errors="ignore")
                raise RuntimeError(f"joern-parse failed:\n{error_msg}")

    def load_cpg(self, path: str) -> Result[str, Exception]:
        """Load a CPG from a file."""
        return self.session.load_cpg(path)

    def execute(self, query: Query) -> Result[list[Match], Exception]:
        """Execute a hoppy Query against the loaded CPG."""
        if not self.session:
            return Failure(
                RuntimeError("Analyzer must be used as a context manager (with Analyzer() as a:)")
            )

        return (
            self.session.run_query(query)
            .bind(self._ensure_list)
            .map(
                lambda raw_results: [
                    Match.from_json(r, query._mvar_names)
                    for r in raw_results
                    if isinstance(r, (dict, list))
                ]
            )
            .map(self._deduplicate_matches)
            .map(self._log_duration)
        )

    def _log_duration(self, results: _T) -> _T:
        if self.verbose:
            import sys

            print(f"[DEBUG] Query took {self.session.last_duration:.3f}s", file=sys.stderr)
        return results

    def _deduplicate_matches(self, matches: list[Match]) -> list[Match]:
        seen = set()
        unique = []

        # Sort matches:
        # 1. Prefer those where the source is NOT a parameter (is a Call/Identifier)
        # 2. Prefer longer code snippets
        def sort_key(m):
            source_is_param = False
            if m.flow:
                source_is_param = "this" in m.flow[0].code.lower() or m.flow[0].code == ""
            return (0 if not source_is_param else 1, -len(m.code))

        for m in sorted(matches, key=sort_key):
            sink_loc = (m.file, m.line or 0)
            source_method = "unknown"
            if m.flow:
                source_method = m.flow[0].method

            bind_sig = tuple(sorted(m.bindings.items()))
            sig = (sink_loc, source_method, bind_sig)

            if sig in seen:
                continue
            seen.add(sig)
            unique.append(m)
        return unique

    @safe
    def _ensure_list(self, raw_results: JSONValue) -> list[Any]:
        match raw_results:
            case list():
                return raw_results
            case dict():
                # If we got a dict (like from slicing), wrap it in a list
                # so the rest of the pipeline works
                return [raw_results]
            case None:
                return []
            case _:
                raise ValueError(f"Query execution returned non-list/dict: {type(raw_results)}")

    def raw_scala(self, scala: str, prelude: str | None = None) -> Result[str, Exception]:
        """Run raw Scala code."""
        return self.session.run_scala(scala, prelude=prelude)

    def list_calls(self, pattern: str = ".*") -> Result[list[str], Exception]:
        """List all unique function calls matching a regex pattern (name or methodFullName)."""
        esc_pattern = json.dumps(pattern)[1:-1]
        scala = (
            f'ujson.Arr(cpg.call.filter(c => (c.name.matches("{esc_pattern}") || '
            f'c.methodFullName.matches("{esc_pattern}")) && '
            f'!c.name.startsWith("<operator>") && '
            f'!c.methodFullName.startsWith("<operator>") && '
            f'!c.methodFullName.contains("\\n") && '
            f'!c.methodFullName.contains("{{")'
            f").methodFullName.distinct.l"
            f".map(v => v: ujson.Value)*)"
        )
        return (
            self.session.run_scala(scala)
            .bind(self.session._parse_json_result)
            .bind(self._ensure_list_or_empty)
        )

    def list_methods(
        self,
        pattern: str = ".*",
        internal_only: bool = False,
        file_pattern: str = ".*",
        entry_points_only: bool = False,
    ) -> Result[list[str], Exception]:
        """List all method definitions matching regex patterns (name or fullName)."""
        import json

        esc_pattern = json.dumps(pattern)[1:-1]
        esc_file = json.dumps(file_pattern)[1:-1]
        internal_filter = " && !m.isExternal" if internal_only else ""
        # Exclude :program from starting points to reduce noise.
        # :program is usually a redundant container for scripts that have other methods.
        extra_filter = ' && m.name != ":program"' if internal_only else ""
        if entry_points_only:
            # Allow lambdas as entry points only if they are top-level
            # (direct children of script/module).
            # This allows AWS Lambda handlers and top-level exported functions to be found,
            # while filtering out the noise of thousands of internal callbacks.
            extra_filter += (
                ' && m.callIn.isEmpty && (!m.name.contains("<lambda>") || '
                'm.fullName.matches(".*(:program|<module>|<global>):<lambda>.*"))'
            )

        scala = (
            f'ujson.Arr(cpg.method.filter(m => (m.name.matches("{esc_pattern}") || '
            f'm.fullName.matches("{esc_pattern}")) && '
            f'm.filename.matches("{esc_file}"){internal_filter}{extra_filter} && '
            f'!m.name.startsWith("<operator>") && '
            f'!m.fullName.startsWith("<operator>") && '
            f'!m.fullName.contains("\\n") && '
            f'!m.fullName.contains("{{")'
            f").fullName.distinct.l"
            f".map(v => v: ujson.Value)*)"
        )
        return (
            self.session.run_scala(scala)
            .bind(self.session._parse_json_result)
            .bind(self._ensure_list_or_empty)
        )

    @safe
    def _ensure_list_or_empty(self, val: JSONValue) -> list[str]:
        match val:
            case list():
                return cast(list[str], val)
            case _:
                return []

    def get_method_details(self, full_name: str) -> Result[dict[str, Any], Exception]:
        """Get detailed information about a method definition."""
        esc_name = json.dumps(full_name)[1:-1]
        scala = f"""
        cpg.method.fullName("{esc_name}").map {{ m =>
            val params = m.parameter.map(p => ujson.Obj(
                "name" -> ujson.Str(p.name),
                "type" -> ujson.Str(p.typeFullName),
                "index" -> ujson.Num(p.order)
            )).l

            val callsOut = m.call.filter(c => !c.name.startsWith("<operator>"))
                .map(c => ujson.Obj(
                    "name" -> ujson.Str(c.name),
                    "fullName" -> ujson.Str(c.methodFullName),
                    "code" -> ujson.Str(c.code)
                )).distinct.l

            val callers = m.callIn.method.map(x => ujson.Str(x.fullName.toString)).distinct.l

            ujson.Obj(
                "fullName" -> ujson.Str(m.fullName),
                "name" -> ujson.Str(m.name),
                "file" -> ujson.Str(m.filename),
                "line" -> m.lineNumber.map(ujson.Num(_)).getOrElse(ujson.Null),
                "params" -> params,
                "callsOut" -> callsOut,
                "callers" -> callers,
                "code" -> ujson.Str(getCode(m))
            )
        }}.headOption.getOrElse(ujson.Null)
        """
        return (
            self.raw_scala(scala, prelude=self.session.prelude)
            .bind(self.session._parse_json_result)
            .map(lambda r: cast(dict[str, Any], r))
        )

    def find_calls(self, pattern: str = ".*") -> Result[list[dict[str, Any]], Exception]:
        """Find rich information about call sites matching a pattern."""
        esc_pattern = json.dumps(pattern)[1:-1]
        scala = f"""
        ujson.Arr(cpg.call.filter(c => c.name.matches("{esc_pattern}") ||
          c.methodFullName.matches("{esc_pattern}"))
          .map(c => ujson.Obj(
            "name" -> ujson.Str(c.name),
            "fullName" -> ujson.Str(c.methodFullName),
            "caller" -> ujson.Str(
              c.method.map(_.fullName).headOption.map(_.toString).getOrElse("<unknown>")
            ),
            "code" -> ujson.Str(c.code),
            "file" -> ujson.Str(c.file.name.headOption.map(_.toString).getOrElse("")),
            "line" -> c.lineNumber.map(ujson.Num(_)).getOrElse(ujson.Null)
          )).l.map(v => v: ujson.Value)*)
        """
        return (
            self.session.run_scala(scala)
            .bind(self.session._parse_json_result)
            .bind(self._ensure_list)
        )

    def data_flow_slice(self, sink_pattern: str, depth: int = 40) -> Result[Slice, Exception]:
        """
        Performs a data-flow slice starting from nodes matching the sink_pattern.
        """
        # Escape for Scala string literal
        esc_sink = json.dumps(sink_pattern)[1:-1]

        scala = f'''
        import io.joern.dataflowengineoss.slicing._
        import io.shiftleft.semanticcpg.language._
        import io.shiftleft.codepropertygraph.generated.nodes._
        val config = DataFlowConfig(sinkPatternFilter = Some("{esc_sink}"), sliceDepth = {depth})
        DataFlowSlicing.calculateDataFlowSlice(cpg, config) match {{
          case None => null
          case Some(slice) =>
            val methodNames = slice.nodes.map(_.parentMethod)
              .filter(m => m != null && m != "").distinct
            val paramMap = methodNames
              .map(m => m -> cpg.method.filter(_.fullName == m).parameter.name.l)
              .toMap
            def nodeById(id: Long) = cpg.id(id).l.headOption

            val extraNodes = methodNames.flatMap {{ m =>
              cpg.method.filter(_.fullName == m).parameter.l.map {{ p =>
                val node = ujson.Obj()
                node("id") = p.id
                node("label") = "METHOD_PARAMETER_IN"
                node("name") = p.name
                node("code") = p.code
                node("typeFullName") = p.typeFullName
                node("parentMethod") = m
                node("parentFile") = p.file.name.l.headOption.getOrElse("")
                node("lineNumber") = p.lineNumber.map(ujson.Num(_)).getOrElse(ujson.Null)
                node("columnNumber") = p.columnNumber.map(ujson.Num(_)).getOrElse(ujson.Null)
                node
              }}
            }}.l

            val sinkIds = slice.nodes.filter {{ n =>
              n.label == "CALL" && (
                (n.name != null && n.name.matches("{esc_sink}")) ||
                (n.code != null && n.code.matches(".*" + "{esc_sink}" + ".*"))
              )
            }}.map(_.id).l

            val originIds = slice.nodes.filter {{ n =>
              (
                (n.label == "METHOD_PARAMETER_IN" ||
                  n.label == "METHOD_PARAMETER_OUT" || n.label == "PARAMETER") &&
                n.name != "this"
              ) ||
              (
                n.label == "IDENTIFIER" &&
                n.name != null &&
                n.name != "this" &&
                n.parentMethod != null &&
                paramMap.getOrElse(n.parentMethod, List()).contains(n.name)
              )
            }}.map(_.id).l

            val paramUsageIds = slice.nodes.flatMap {{ n =>
              nodeById(n.id) match {{
                case Some(_: Identifier)
                    if n.name != null &&
                       n.name != "this" &&
                       n.parentMethod != null &&
                       paramMap.getOrElse(n.parentMethod, List()).contains(n.name) =>
                  Some(n.id)
                case _ => None
              }}
            }}.l

            val json = ujson.read(slice.toJson)
            json("sinkIds") = sinkIds
            json("originIds") = originIds
            json("paramUsageIds") = paramUsageIds
            json("extraNodes") = extraNodes
            json
        }}
        '''
        return (
            self.raw_scala(scala)
            .bind(self.session._parse_json_result)
            .map(lambda r: Slice.from_json(cast(dict, r)) if r else Slice(nodes=[], edges=[]))
            .map(self._log_duration)
        )

    def usage_slice(
        self, min_calls: int = 1, exclude_operators: bool = False
    ) -> Result[dict[str, Any], Exception]:
        """
        Performs a usages slice, tracing locals and parameters.
        """
        scala = f"""
        import io.joern.dataflowengineoss.slicing._
        val config = UsagesConfig(minNumCalls = {min_calls},
          excludeOperatorCalls = {str(exclude_operators).lower()})
        ujson.read(UsageSlicing.calculateUsageSlice(cpg, config).toJson)
        """
        return (
            self.raw_scala(scala)
            .bind(self.session._parse_json_result)
            .map(lambda r: cast(dict[str, Any], r))
            .map(self._log_duration)
        )

    def get_api_summary(self) -> Result[dict[str, list[str]], Exception]:
        """Returns a summary of external API calls found in the codebase, grouped by 'module'."""
        scala = """
        ujson.Arr(cpg.call
          .filter(c => c.methodFullName.contains(".") && !c.methodFullName.startsWith("<operator>"))
          .map(c => c.methodFullName)
          .distinct.l.map(v => v: ujson.Value)*)
        """
        return (
            self.session.run_scala(scala)
            .bind(self.session._parse_json_result)
            .bind(self._ensure_list_or_empty)
            .map(self._group_api_summary)
        )

    def discover_wrappers(
        self, heuristics: list["DiscoveryHeuristic"]
    ) -> Result[list[dict[str, Any]], Exception]:
        """
        Heuristic scan to discover internal methods that wrap dangerous external APIs.
        Returns a list of wrappers with details about the dangerous calls they make.
        """
        import json

        # Prepare heuristics for Scala
        heuristics_json = json.dumps(
            [
                {
                    "category": h.category,
                    "patterns": h.patterns,
                    "weight": h.weight,
                    "suspicious_params": h.suspicious_params,
                }
                for h in heuristics
            ]
        )

        scala = f"""
        import io.joern.dataflowengineoss.language._
        import io.shiftleft.semanticcpg.language._
        import ujson._

        val heuristics = ujson.read(\"\"\"{heuristics_json}\"\"\").arr
        val allPatterns = heuristics.flatMap(_.obj(\"patterns\").arr.map(_.str)).l

        def getHeuristic(name: String, fullName: String) = {{
             heuristics.find {{ h =>
                h.obj(\"patterns\").arr.map(_.str).exists {{ p =>
                    fullName.matches(p) || name.matches(p)
                }}
             }}
        }}

        val results = cpg.method
            .filter(m => !m.isExternal && !m.name.startsWith("<operator>"))
            .where(_.file.name(".*"))
            .map {{ m =>
                val dangerousCalls = m.call.filter {{ c =>
                    allPatterns.exists {{ p =>
                        c.methodFullName.matches(p) || c.name.matches(p)
                    }}
                }}.l
                val flowConfirmed = dangerousCalls.flatMap {{ c =>
                    if (c.name.nonEmpty &&
                        c.methodFullName.nonEmpty &&
                        c.methodFullName != "<unknown>") {{
                         val taintingParams = m.parameter
                            .filter(p => c.argument.reachableBy(p).nonEmpty)
                            .name.l
                         if (taintingParams.nonEmpty) {{
                             val h = getHeuristic(c.name, c.methodFullName).get
                             val baseWeight = h.obj(\"weight\").num.toInt
                             val suspParams = h.obj(\"suspicious_params\")
                                .arr.map(_.str).toSet

                             // Score boost for suspicious parameter names
                             val isSuspicious = taintingParams.exists(
                                p => suspParams.contains(p.toLowerCase)
                             )
                             val boost = if (isSuspicious) 5 else 0
                             val score = baseWeight + boost

                             Some(ujson.Obj(
                                \"name\" -> c.name,
                                \"fullName\" -> c.methodFullName,
                                \"category\" -> h.obj(\"category\").str,
                                \"score\" -> score,
                                \"line\" -> c.lineNumber.getOrElse(-1),
                                \"taintedBy\" -> taintingParams
                             ))
                         }} else {{
                             None
                         }}
                    }} else {{
                        None
                    }}
                }}.l
                (m, flowConfirmed)
            }}
            .filter(_._2.nonEmpty)
            .map {{ case (m, dangerousCalls) =>
                 // Deduplicate calls by (category, fullName)
                 val dedupedCalls = dangerousCalls.groupBy(c =>
                    (c.obj(\"category\").str, c.obj(\"fullName\").str)
                 ).map {{ case ((category, fullName), instances) =>
                    val name = instances.head.obj(\"name\").str
                    val scores = instances.map(_.obj(\"score\").num.toInt)
                    val maxScore = scores.max
                    val allTaintedBy = instances
                        .flatMap(_.obj(\"taintedBy\").arr.map(_.str))
                        .distinct.l
                    ujson.Obj(
                      \"name\" -> name,
                      \"fullName\" -> fullName,
                      \"category\" -> category,
                      \"score\" -> maxScore,
                      \"taintedBy\" -> allTaintedBy
                    )
                 }}.l
                 val maxScore = dedupedCalls.map(_.obj(\"score\").num.toInt).max

                 // Recursive parent method name resolution
                 def getMethodPath(
                    curr: io.shiftleft.codepropertygraph.generated.nodes.Method
                 ): String = {{
                    val p = curr.astIn.isMethod.headOption
                    p match {{
                        case Some(parent) if parent.name != \":program\" =>
                            s\"${{getMethodPath(parent)}}.${{curr.name}}\"
                        case _ => curr.name
                    }}
                 }}

                 val displayName = getMethodPath(m)

                 ujson.Obj(
                   \"name\" -> displayName,
                   \"fullName\" -> m.fullName,
                   \"file\" -> m.filename,
                   \"line\" -> m.lineNumber.getOrElse(-1),
                   \"params\" -> m.parameter.name.l,
                   \"score\" -> maxScore,
                   \"dangerousCalls\" -> dedupedCalls
                 )
            }}.l
        ujson.Arr(results*)
        """
        return (
            self.session.run_scala(scala)
            .bind(self.session._parse_json_result)
            .bind(self._ensure_list)
        )

    def get_call_graph(
        self,
        method_names: list[str],
        direction: str = "callee",
        depth: int = 5,
        exclude_patterns: list[str] | None = None,
        heuristics: list["DiscoveryHeuristic"] | None = None,
        barrier_heuristics: list["DiscoveryHeuristic"] | None = None,
        barrier_predicate: str | None = None,
        include_conditions: bool = False,
        include_backward_trace: bool = False,
        include_external_pattern: str | None = None,
        interesting_only: bool = False,
    ) -> Result[list[dict[str, Any]], Exception]:
        """
        Retrieves call graphs (trees) starting from multiple methods.
        """
        import json

        methods_json = json.dumps(method_names)
        exclude_json = json.dumps(exclude_patterns or [])
        heuristics_json = json.dumps(
            [{"category": h.category, "patterns": h.patterns} for h in (heuristics or [])]
        )
        barriers_json = json.dumps(
            [{"category": h.category, "patterns": h.patterns} for h in (barrier_heuristics or [])]
        )
        # Default to a predicate that matches nothing if not provided
        barrier_pred = barrier_predicate or "((_: nodes.StoredNode) => false)"
        display_conds_scala = "true" if include_conditions else "false"
        include_trace_scala = "true" if include_backward_trace else "false"
        include_ext_scala = (
            json.dumps(include_external_pattern) if include_external_pattern else '""'
        )
        interesting_only_scala = "true" if interesting_only else "false"

        scala = f"""
        import io.shiftleft.codepropertygraph.generated.nodes
        import io.shiftleft.semanticcpg.language._
        import io.joern.dataflowengineoss.language._
        import ujson._

        val startMethodsList = ujson.read(\"\"\"{methods_json}\"\"\").arr.map(_.str).l
        val excludeList = ujson.read(\"\"\"{exclude_json}\"\"\").arr.map(_.str).l
        val heuristics = ujson.read(\"\"\"{heuristics_json}\"\"\").arr
        val barrierHeuristics = ujson.read(\"\"\"{barriers_json}\"\"\").arr
        val isAuthBarrier = {barrier_pred}
        val includeConditions = {display_conds_scala}
        val includeTrace = {include_trace_scala}
        val includeExternalPattern = {include_ext_scala}
        val interestingOnly = {interesting_only_scala}

        def getBarriers(m: nodes.Method): List[String] = {{
          if (isAuthBarrier(m)) {{
             val fromAnnotation = (m.start.annotation ++ m.typeDecl.annotation).filter {{ a =>
                barrierHeuristics.exists(_.obj("patterns").arr.map(_.str).exists(p =>
                  a.name.matches(p)))
             }}.code.l

             val fromCalls = m.call.filter {{ c =>
                barrierHeuristics.exists(_.obj("patterns").arr.map(_.str).exists(p =>
                  c.methodFullName.matches(p) || c.name.matches(p)))
             }}.code.l

             if (fromAnnotation.nonEmpty || fromCalls.nonEmpty) {{
                (fromAnnotation ++ fromCalls).distinct
             }} else if (m.name.toLowerCase.matches(
                ".*(auth|login|verify|perm|authorize|secure).*"
             )) {{
                List(m.name)
             }} else {{
                List.empty
             }}
          }} else List.empty
        }}

        def isExcluded(name: String): Boolean = {{
          excludeList.exists(p => name.matches(p))
        }}

        def getCategory(name: String): Option[String] = {{
          heuristics.find {{ h =>
            h.obj("patterns").arr.map(_.str).exists(p => name.matches(p))
          }}.map(_.obj("category").str)
        }}

        def buildTree(
            curr: nodes.Method,
            currentDepth: Int,
            visited: Set[String],
            activeBarriers: List[String],
            callerFile: String = ""
        ): ujson.Obj = {{
          val fullName = curr.fullName
          val node = ujson.Obj(
            "name" -> curr.name,
            "fullName" -> fullName,
            "file" -> curr.filename,
            "callerFile" -> callerFile,
            "line" -> curr.lineNumber.getOrElse(-1)
          )

          val category = getCategory(fullName)
          if (category.isDefined) {{
             node("category") = category.get
          }}

          // Identify barriers on the current method node
          val currentBarriers = getBarriers(curr)

          if (currentBarriers.nonEmpty) {{
             node("barriers") = ujson.Arr(currentBarriers.map(ujson.Str(_))*)
          }} else if (activeBarriers.nonEmpty) {{
             node("isDominated") = true
          }}

          if (currentDepth >= {depth} || visited.contains(fullName)) {{
             node("children") = ujson.Arr()
             return node
          }}

          var localVisited = visited + fullName
          val nextActiveBarriers = if (currentBarriers.nonEmpty) currentBarriers else activeBarriers

          def expand(
            m: nodes.Method, expVisited: Set[String]
          ): List[(nodes.Method, List[String], List[String])] = {{
             if ("{direction}" == "caller") {{
                return m.callIn.method
                  .filter(x => !isExcluded(x.fullName))
                  .distinct.l
                  .map(x => (x, List.empty, List.empty))
             }}

             val directCalls = m.call.filter(c => !c.name.startsWith("<operator>")).l

             // Find methods nested in the AST (lambdas defined inside the current method)
             val nestedMethods = m.ast.isMethod.filter(l => l != m && l.name.contains("<lambda>")).l

             val callTargets = directCalls.flatMap {{ c =>
                val directTargets = (c.callee.l ++ c.argument.isMethodRef.referencedMethod.l)
                val targets = directTargets.flatMap {{ m =>
                  if (m.isExternal && includeExternalPattern.nonEmpty &&
                      m.fullName.matches(includeExternalPattern)) {{
                    val parts = m.fullName.split(":")
                    if (parts.length >= 2) {{
                       val className = java.util.regex.Pattern.quote(parts(parts.length - 2))
                       val methodName = java.util.regex.Pattern.quote(parts.last)
                       val internalMatches = cpg.method
                        .isExternal(false)
                        .nameExact(parts.last)
                        .fullName(s".*${{className}}:${{methodName}}")
                        .l
                       if (internalMatches.nonEmpty) internalMatches else List(m)
                    }} else {{
                       val internalMatches = cpg.method.isExternal(false).nameExact(m.name).l
                       if (internalMatches.nonEmpty) internalMatches else List(m)
                    }}
                  }} else List(m)
                }}.filter(x => !isExcluded(x.fullName)).distinct.l

                // Only query conditions if requested to save performance
                val conditions = if (includeConditions) {{
                    c.start.controlledBy.code.l
                      .filter(cond => !cond.contains("_iterator") &&
                                      !cond.contains("_result") &&
                                      !cond.contains(".next()") &&
                                      cond.length < 100)
                      .distinct
                }} else List.empty

                targets.map {{ t =>
                   val tCategory = getCategory(t.fullName)

                   val traces = if (includeTrace && tCategory.isDefined) {{
                      // Trace arguments (index > 0) to method parameters, filtering out noise
                      val noisy = Set(
                        "this", "self", "resolve", "reject", "callback",
                        "cb", "next", "res", "req", "ctx"
                      )
                      c.argument
                        .filter(a => a.argumentIndex > 0 && !a.isInstanceOf[nodes.Literal])
                        .flatMap {{ arg =>
                           arg.start.reachableByFlows(m.parameter).map(_.elements.head).code
                             .filterNot(s => noisy.contains(s.toLowerCase) || s.contains("this."))
                             .distinct.l.map(s => s"arg: ${{arg.code}} <- param: $s")
                        }}.l.distinct
                   }} else List.empty

                   (t, conditions, traces)
                }}
             }}

             val nestedTargets = nestedMethods
              .filter(l => !isExcluded(l.fullName))
              .map(l => (l, List.empty[String], List.empty[String]))

             (callTargets ++ nestedTargets).flatMap {{ case (t, conditions, traces) =>
                if (t.name == ":program" && !expVisited.contains(t.fullName)) {{
                   expand(t, expVisited + t.fullName).map {{ case (em, ec, et) =>
                     (em, (conditions ++ ec).distinct, (traces ++ et).distinct)
                   }}
                }} else {{
                   List((t, conditions, traces))
                }}
             }}
          }}

          val childrenData = expand(curr, localVisited)

          // Group by target fullName to merge conditions and traces from multiple call sites
          val children = childrenData.groupBy(_._1.fullName).map {{ case (fn, datas) =>
             val m = datas.head._1
             val mergedConditions = datas.flatMap(_._2).distinct
             val mergedTraces = datas.flatMap(_._3).distinct

             val mCategory = getCategory(m.fullName)
             val shouldKeep = if (heuristics.nonEmpty) {{
                mCategory.isDefined || !m.isExternal ||
                  (includeExternalPattern.nonEmpty && m.fullName.matches(includeExternalPattern))
             }} else true

             if (shouldKeep) {{
                val childNode = buildTree(
                  m, currentDepth + 1, localVisited, nextActiveBarriers, curr.filename
                )
                if (mergedConditions.nonEmpty) {{
                   childNode("conditions") = ujson.Arr(mergedConditions.map(ujson.Str(_))*)
                }}
                if (mergedTraces.nonEmpty) {{
                   childNode("traces") = ujson.Arr(mergedTraces.map(ujson.Str(_))*)
                }}
                Some(childNode)
             }} else {{
                // If it's excluded but matches a heuristic (dangerous sink), we KEEP it
                if (mCategory.isDefined) {{
                   val childNode = buildTree(
                     m, currentDepth + 1, localVisited, nextActiveBarriers, curr.filename
                   )
                   Some(childNode)
                }} else None
             }}
          }}.flatten.toList.sortBy(_.obj("name").str)

          node("children") = ujson.Arr(children*)
          node
        }}

        val results = startMethodsList.flatMap {{ mName =>
          cpg.method.fullNameExact(mName).headOption.map {{ m =>
            buildTree(m, 0, Set.empty, List.empty, m.filename)
          }}
        }}

        def filterInteresting(node: ujson.Value): Option[ujson.Value] = {{
          if (node.obj.contains("category")) return Some(node)
          val children = node.obj("children").arr.flatMap(c => filterInteresting(c)).l
          if (children.nonEmpty) {{
            node.obj("children") = ujson.Arr(children*)
            Some(node)
          }} else None
        }}

        val filtered = if (interestingOnly) {{
            results.flatMap(r => filterInteresting(r)).l
        }} else results

        ujson.Arr(filtered*)
        """
        return (
            self.session.run_scala(scala)
            .bind(self.session._parse_json_result)
            .bind(self._ensure_list)
        )

    def _group_api_summary(self, fullnames: list[str]) -> dict[str, list[str]]:
        summary: dict[str, list[str]] = {}
        for fn in fullnames:
            if not isinstance(fn, str):
                continue
            # Handle possible Scala-style fullnames with extra info
            if ":" in fn:
                parts = fn.split(":")
                if len(parts) > 1:
                    fn = parts[1]

            match fn.split("."):
                case [module, *_, _] if module:
                    summary.setdefault(module, []).append(fn)
                case _:
                    summary.setdefault("builtins", []).append(fn)
        return summary
