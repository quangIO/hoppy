import json
from typing import Any, TypeVar, cast

from returns.result import Failure, Result, safe

from .core.manager import JoernSession, JSONValue
from .core.match import Match
from .core.slicing import Slice
from .dsl.query import Query

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
    ) -> Result[str, Exception]:
        """Import code into the analysis session."""
        return self.session.import_code(
            path,
            language=language,
            joern_parse_args=joern_parse_args,
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

        subprocess.run([joern_parse_cmd, src_path, "--output", out_path], check=True)

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

    def list_methods(self, pattern: str = ".*") -> Result[list[str], Exception]:
        """List all method definitions matching a regex pattern (name or fullName)."""
        esc_pattern = json.dumps(pattern)[1:-1]
        scala = (
            f'ujson.Arr(cpg.method.filter(m => (m.name.matches("{esc_pattern}") || '
            f'm.fullName.matches("{esc_pattern}")) && '
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
