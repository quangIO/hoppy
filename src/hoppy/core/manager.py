import logging
import os
import re
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Any, TypeVar
from urllib.parse import urlparse

import requests
from returns.result import Result, Success, safe

from .. import installer

logger = logging.getLogger(__name__)

type JSONValue = dict[str, Any] | list[Any] | str | int | float | bool | None

_T = TypeVar("_T")


class JoernExecutionError(Exception):
    """Raised when a Joern query fails or returns an error."""

    pass


COMMON_PRELUDE = """
import io.joern.dataflowengineoss.slicing._
import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.semanticcpg.language._
import upickle.default._

def resolveTarget(n: nodes.StoredNode): nodes.StoredNode = {
  if (n.isInstanceOf[nodes.Call] && !n.asInstanceOf[nodes.Call].name.startsWith("<operator>"))
    n
  else n.start.collectAll[nodes.AstNode].astParent.collectAll[nodes.Call].headOption.getOrElse(n)
}

def getCode(n: nodes.StoredNode): String = {
  n.start.collectAll[nodes.CfgNode].code.headOption.getOrElse(
    n.start.collectAll[nodes.AstNode].code.headOption.getOrElse("")
  )
}

def getBinding(n: nodes.StoredNode, index: Int): String = {
  if (index < 0) getCode(n)
  else n match {
    case c: nodes.Call => c.start.argument(index).code.headOption.getOrElse("")
    case _ => getCode(n)
  }
}

def unifyStep(
  n: nodes.StoredNode, pred: nodes.StoredNode => Boolean,
  expected: String, index: Int
): Boolean = {
  if (pred(n)) {
    val v = getBinding(n, index)
    v != "" && v == expected
  } else {
    val callNode = n.start.collectAll[nodes.AstNode].astParent.collectAll[nodes.Call].headOption
    callNode.exists { c =>
      if (pred(c)) {
        val v = getBinding(c, index)
        v != "" && v == expected
      } else false
    }
  }
}

def getMethodFullName(n: nodes.StoredNode): String = {
  n.start.collectAll[nodes.CfgNode].method.map(m => {
    val fn = m.filename
    val fullName = m.fullName
    if (fn != "" && fn != "N/A" && fullName != "" && !fullName.startsWith(fn) &&
      !fullName.startsWith("<operator>")) {
      fn + ":" + fullName
    } else {
      fullName
    }
  }).headOption.getOrElse("<unknown>")
}

def getClassName(n: nodes.StoredNode): String = {
  n.start.map(node =>
    node match {
      case m: nodes.Method =>
        val typeDecl = m.definingTypeDecl.fullName.headOption.getOrElse("")
        if (typeDecl != "" && typeDecl != "<unknown>") typeDecl
        else {
          val parent = m.astParentFullName
          if (parent != null && parent != "" && parent != "<unknown>" &&
            m.astParentType == "TYPEDECL") {
            parent
          } else {
            val full = m.fullName.split(":").head.split("\\\\(").head
            if (full.contains(".")) {
              val parts = full.split("\\\\.")
              if (parts.length >= 2) parts.dropRight(1).mkString(".") else full
            } else {
              val filename = m.filename
              if (filename != null && filename != "" && filename != "N/A") {
                filename.split("[/\\\\\\\\]").last.split("\\\\.").head
              } else "<unknown>"
            }
          }
        }
      case _ =>
        val method = node.start.collectAll[nodes.CfgNode].method.headOption
        method.map { m =>
          val typeDecl = m.definingTypeDecl.fullName.headOption.getOrElse("")
          if (typeDecl != "" && typeDecl != "<unknown>") typeDecl
          else {
            val parent = m.astParentFullName
            if (parent != null && parent != "" && parent != "<unknown>" &&
              m.astParentType == "TYPEDECL") parent
            else "<unknown>"
          }
        }.getOrElse("<unknown>")
    }
  ).headOption.getOrElse("<unknown>")
}

def getLocation(n: nodes.StoredNode) = {
  val l = io.shiftleft.semanticcpg.language.locationCreator(n)
  ujson.Obj(
    "filename" -> l.filename,
    "line" -> l.lineNumber.map(n => ujson.Num(n.toDouble)).getOrElse(ujson.Null),
    "column" -> n.propertyOption[Integer]("COLUMN_NUMBER").map(n => ujson.Num(n.toDouble))
      .getOrElse(ujson.Null),
    "method" -> l.methodFullName,
    "code" -> n.propertyOption[String]("CODE").getOrElse(""),
    "lineNumberEnd" -> n.propertyOption[Integer]("LINE_NUMBER_END").map(n => ujson.Num(n.toDouble))
      .getOrElse(ujson.Null),
    "columnNumberEnd" -> n.propertyOption[Integer]("COLUMN_NUMBER_END")
      .map(n => ujson.Num(n.toDouble)).getOrElse(ujson.Null)
  )
}
"""


def find_free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


DEFAULT_JVM_OPTS = [
    "-J-Xmx8g",
    "-J-Xms8g",
    "-J-XX:+UseG1GC",
    "-J-XX:+UseStringDeduplication",
]


class JoernSession:
    """
    Manages a Joern session using the Joern server (HTTP).
    By default, it starts a local server on a free port with a unique workspace
    to allow for concurrent analysis.
    """

    def __init__(
        self,
        bin_path: str = "joern",
        port: int | None = None,
        workspace: str | None = None,
        server_url: str | None = None,
        jvm_opts: list[str] | None = None,
    ):
        # Auto-discover or install Joern if using the default path
        if bin_path == "joern":
            joern_executable = installer.get_joern_executable()
            if joern_executable is None:
                # Joern not found, install it automatically with rich progress
                from rich.console import Console

                console = Console()
                joern_executable = installer.ensure_joern_installed(console=console)
            self.bin_path = str(joern_executable)
        else:
            self.bin_path = bin_path

        self._explicit_server = server_url is not None
        self.jvm_opts = jvm_opts if jvm_opts is not None else DEFAULT_JVM_OPTS

        if self._explicit_server:
            self.server_url = server_url
            self.workspace = workspace
        else:
            self.port = port if port is not None else find_free_port()
            self.server_url = f"http://127.0.0.1:{self.port}"

            if workspace is None:
                import tempfile

                self._tmp_workspace = tempfile.TemporaryDirectory(prefix="hoppy-workspace-")
                self.workspace = self._tmp_workspace.name
            else:
                self.workspace = workspace
                self._tmp_workspace = None

        self.server_process: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self._is_closing = False
        self.prelude = COMMON_PRELUDE
        self.last_duration: float = 0.0
        self._prelude_injected = False
        self._tmp_parse_workspace: tempfile.TemporaryDirectory | None = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def start(self):
        """Starts the Joern session by ensuring a server is running."""
        if self._is_server_alive():
            self._inject_prelude()
            return self

        if self._explicit_server:
            raise RuntimeError(f"Explicit Joern server not reachable at {self.server_url}")

        # Start a local server
        parsed = urlparse(self.server_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8080

        # We start the server in the background
        # We specify the workspace path to avoid conflicts
        cmd = (
            [
                self.bin_path,
            ]
            + self.jvm_opts
            + [
                "--server",
                "--server-host",
                host,
                "--server-port",
                str(port),
                "--nocolors",
            ]
        )

        if self.workspace:
            # Joern uses this system property for workspace path
            cmd.insert(1, f"-J-Djoern.baseDirectory={self.workspace}")

        self.server_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )

        # Wait for server to be ready
        start_time = time.time()
        while time.time() - start_time < 60:
            if self._is_server_alive():
                self._inject_prelude()
                return self
            time.sleep(1)

        self.close()
        raise RuntimeError(f"Joern server failed to start at {self.server_url} within 60 seconds")

    def _is_server_alive(self) -> bool:
        try:
            response = requests.post(
                f"{self.server_url}/query-sync",
                json={"query": "val _ = 1"},
                timeout=2,
            )
            return response.status_code == 200
        except Exception:
            return False

    def _inject_prelude(self):
        """Injects the common prelude into the session once per server."""
        from returns.result import Success

        if self.prelude and not self._prelude_injected:
            # Check if prelude is already loaded on the server
            # We use a try-catch in Scala to see if resolveTarget is defined
            check_script = 'try { resolveTarget(null); "YES" } catch { case _: Throwable => "NO" }'
            res = self.send_command(check_script)
            if isinstance(res, Success) and "YES" in res.unwrap():
                self._prelude_injected = True
                return

            # Inject at top-level so helper defs remain available for later queries
            script = self.prelude.strip() + '\n"PRELUDE_LOADED"'
            res = self.send_command(script)
            if isinstance(res, Success):
                self._prelude_injected = True

    def _strip_ansi(self, text: str) -> str:
        ansi_escape = re.compile(r"\x1B(?:[@-Z\-_]|\[[0-9?]*[ -/]*[@-~])")
        return ansi_escape.sub("", text)

    @safe
    def send_command(self, cmd: str) -> str:
        """Sends a command to the server and returns the raw output."""
        start_time = time.time()
        try:
            timeout_s = 120
            timeout_env = os.getenv("HOPPY_JOERN_TIMEOUT")
            if timeout_env:
                try:
                    timeout_s = max(1, int(timeout_env))
                except ValueError:
                    timeout_s = 120
            response = requests.post(
                f"{self.server_url}/query-sync",
                json={"query": cmd},
                timeout=timeout_s,
            )
            response.raise_for_status()
            data = response.json()
            if not data.get("success"):
                # Joern errors are often in stdout even if success is false
                stdout = str(data.get("stdout", ""))
                if "-- [E" in stdout:
                    raise ValueError(f"Joern execution error: {stdout.strip()}")
                raise RuntimeError(f"Joern command failed: {stdout}")

            stdout = str(data.get("stdout", ""))
            return self._strip_ansi(stdout)
        finally:
            self.last_duration = time.time() - start_time

    def import_code(
        self,
        path: str,
        language: str | None = None,
        joern_parse_args: list[str] | None = None,
        use_cache: bool = True,
    ) -> Result[str, Exception]:
        from .cache import CpgCache

        abs_path = os.path.abspath(path)
        self.run_scala("workspace.projects.foreach(p => close(p.name))")

        if use_cache:
            cache = CpgCache()
            cached_path = cache.get(abs_path, language=language, joern_args=joern_parse_args)
            if cached_path:
                logger.info(f"Using cached CPG for {abs_path}")
                return self.load_cpg(cached_path)

        # For everything we want to cache, we prefer using joern-parse
        # because it's a standalone tool that produces a solid CPG file.
        if use_cache or os.path.isdir(abs_path) or joern_parse_args:
            return self._import_with_joern_parse(
                abs_path,
                language=language,
                joern_parse_args=joern_parse_args,
                use_cache=use_cache,
            )

        # For single files where caching is disabled, we can use importCode directly
        lang_arg = f', language="{language}"' if language else ""
        project_name = os.path.basename(abs_path)
        cmd = f'importCode(inputPath="{abs_path}", projectName="{project_name}"{lang_arg})'
        return self.send_command(cmd).map(self._report_import_status)

    def _import_with_joern_parse(
        self,
        abs_path: str,
        language: str | None,
        joern_parse_args: list[str] | None,
        use_cache: bool = True,
    ) -> Result[str, Exception]:
        if self._explicit_server:
            parsed = urlparse(self.server_url or "")
            host = parsed.hostname or ""
            if host not in {"127.0.0.1", "localhost", "::1"}:
                raise RuntimeError("joern-parse args are only supported with a local Joern server.")

        workspace = self._parse_workspace()
        output_path = os.path.join(
            workspace,
            f"hoppy-{uuid.uuid4().hex}.cpg.bin.zip",
        )

        # Derive joern-parse path from joern executable
        joern_parse_cmd = "joern-parse"
        if self.bin_path != "joern":
            # If using custom joern path, derive joern-parse path
            joern_dir = os.path.dirname(self.bin_path)
            joern_parse_path = os.path.join(joern_dir, "joern-parse")
            if os.path.exists(joern_parse_path):
                joern_parse_cmd = joern_parse_path

        cmd = [joern_parse_cmd, abs_path, "--output", output_path]
        if language:
            cmd.extend(["--language", language])

        if joern_parse_args:
            if "--frontend-args" in joern_parse_args:
                cmd.extend(joern_parse_args)
            else:
                cmd.append("--frontend-args")
                cmd.extend(joern_parse_args)

        log_path = os.path.join(workspace, "joern-parse.log")
        with open(log_path, "w") as log_file:
            try:
                subprocess.run(
                    cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                # On failure, read the log and raise a more descriptive error
                if os.path.exists(log_path):
                    with open(log_path) as f:
                        log_content = f.read()
                    raise RuntimeError(
                        f"joern-parse failed with exit code {e.returncode}:\n{log_content}"
                    ) from e
                raise

        res = self.send_command(f'importCpg("{output_path}")').map(self._report_import_status)

        if use_cache and isinstance(res, Success):
            from .cache import CpgCache

            CpgCache().put(abs_path, output_path, language=language, joern_args=joern_parse_args)

        return res

    def _parse_workspace(self) -> str:
        if self.workspace:
            return self.workspace
        if not self._tmp_parse_workspace:
            self._tmp_parse_workspace = tempfile.TemporaryDirectory(prefix="hoppy-parse-")
        return self._tmp_parse_workspace.name

    def _report_import_status(self, output: str) -> str:
        if "error" in output.lower():
            print(f"Warning during import: {output}")
        return output

    def save_cpg(self, out_path: str) -> Result[str, Exception]:
        abs_path = os.path.abspath(out_path)
        return self.send_command(f'cpg.toBinary("{abs_path}")')

    def load_cpg(self, cpg_path: str) -> Result[str, Exception]:
        abs_path = os.path.abspath(cpg_path)
        # Use importCpg directly, Joern will handle workspace integration.
        # We don't close all projects here to avoid race conditions or workspace corruption.
        return self.send_command(f'importCpg("{abs_path}")')

    def _wrap_script(self, scala_code: str) -> str:
        """Wraps Scala code in a protocol for robust output parsing."""
        return f"""
import upickle.default._
try {{
  val result = {{
{scala_code}
  }};
  val output = (result: Any) match {{
    case v: ujson.Value => ujson.write(v)
    case s: String => s
    case _ =>
      try {{
        val jsonStr = List(result).toJson
        ujson.read(jsonStr).arr.head.toString
      }} catch {{ case _: Throwable => result.toString }}
  }}
  val startMarker = "---HOPPY" + "-START---"
  val endMarker = "---HOPPY" + "-END---"
  startMarker + "\\n" + output + "\\n" + endMarker
}} catch {{
  case e: Throwable =>
    val sw = new java.io.StringWriter
    e.printStackTrace(new java.io.PrintWriter(sw))
    val msg = if (e.getMessage != null) e.getMessage else "No message"
    val errorMarker = "---HOPPY" + "-ERROR---"
    val endMarker = "---HOPPY" + "-END---"
    errorMarker + "\\n" + msg + "\\n" + sw.toString + "\\n" + endMarker
}}
"""

    def run_scala(self, scala: str, prelude: str | None = None) -> Result[str, Exception]:
        """
        Runs Scala code, optionally prepending a prelude and wrapping in a block.
        """
        import textwrap

        body = textwrap.dedent(scala).strip()

        if prelude is not None:
            header = prelude.strip()
            # We simply concat; _wrap_script puts it in a block via `val result = { ... }`
            full_script = header + "\n" + body
        else:
            full_script = body

        wrapped_script = self._wrap_script(full_script)
        logger.debug("Executing Scala script:\n%s", wrapped_script)

        return self.send_command(wrapped_script)

    def run_query(self, query, format="json") -> Result[JSONValue, Exception]:
        """Runs a Query object and returns parsed JSON if possible."""
        scala = query.generate_scala()
        res = self.run_scala(scala, prelude=self.prelude)
        if format == "json":
            return res.bind(self._parse_json_result)
        return res

    @safe
    def _parse_json_result(self, raw: str) -> JSONValue:
        import json

        logger.debug("Raw Joern output:\n%s", raw)

        start_marker = "---HOPPY-START---"
        end_marker = "---HOPPY-END---"
        error_marker = "---HOPPY-ERROR---"

        # Check for error marker first
        if error_marker in raw:
            # Extract error message
            parts = raw.split(error_marker)
            if len(parts) > 1:
                # The error message is everything after the marker until end_marker or end of string
                error_part = parts[1]
                if end_marker in error_part:
                    error_msg = error_part.split(end_marker)[0].strip()
                else:
                    error_msg = error_part.strip()
                raise JoernExecutionError(f"Scala execution failed:\n{error_msg}")
            raise JoernExecutionError("Scala execution failed with unknown error.")

        # Find content between START and END
        if start_marker in raw and end_marker in raw:
            content = raw.split(start_marker)[1].split(end_marker)[0].strip()
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                if content == "()" or content == "":
                    return None
                return content

        # If we wrapped it but didn't find markers, something went wrong
        # with the script execution output
        if start_marker not in raw:
            # Check for common Scala/Joern error indicators in stdout
            error_indicators = [
                "error found",
                "Not Found Error",
                "Syntax Error",
                "Type Error",
                "MappingException",
            ]
            if any(ind in raw for ind in error_indicators):
                raise JoernExecutionError(f"Scala compilation or execution failed:\n{raw.strip()}")

        raise JoernExecutionError(f"No JSON found in Joern output. Raw output:\n{raw[:1000]}...")

    def close(self):
        """Terminates the Joern server process if we started it and cleans up workspace."""
        if self._is_closing:
            return
        self._is_closing = True

        if self.server_process:
            try:
                import signal

                os.killpg(os.getpgid(self.server_process.pid), signal.SIGTERM)
                self.server_process.wait(timeout=10)
            except Exception:
                if self.server_process:
                    self.server_process.kill()
            finally:
                self.server_process = None

        if hasattr(self, "_tmp_workspace") and self._tmp_workspace:
            try:
                self._tmp_workspace.cleanup()
            except Exception:
                pass

        if self._tmp_parse_workspace:
            try:
                self._tmp_parse_workspace.cleanup()
            except Exception:
                pass
