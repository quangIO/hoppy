import hashlib
import os
import subprocess
import sys
import time
from urllib.parse import urlparse

import pytest
import requests

sys.path.insert(0, os.path.abspath("src"))

from hoppy import Analyzer, installer


def _get_joern_parse_cmd() -> str:
    """Get the joern-parse command, resolving it from the joern executable if needed."""
    # Try to find joern-parse via the joern executable path
    joern_executable = installer.get_joern_executable()
    if joern_executable:
        joern_dir = os.path.dirname(joern_executable)
        joern_parse_path = os.path.join(joern_dir, "joern-parse")
        if os.path.exists(joern_parse_path):
            return joern_parse_path

    # Fall back to PATH
    return "joern-parse"


def _wait_for_server(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(url, timeout=2)
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"Joern server not reachable at {url}")


@pytest.fixture(scope="session")
def analyzer():
    server_url = os.environ.get("HOPPY_JOERN_SERVER_URL")
    autostart = os.environ.get("HOPPY_JOERN_SERVER_AUTOSTART") == "1"
    persist = os.environ.get("HOPPY_JOERN_SERVER_PERSIST") == "1"

    use_server = bool(server_url) or autostart
    if use_server and not server_url:
        server_url = "http://localhost:8080"

    server_proc = None
    if use_server and autostart:
        parsed = urlparse(server_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8080
        server_proc = subprocess.Popen(
            [
                "joern",
                "--server",
                "--server-host",
                host,
                "--server-port",
                str(port),
                "--nocolors",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )

    analyzer = Analyzer(use_server=use_server, server_url=server_url)
    analyzer._current_cpg = None

    if use_server and server_url:
        _wait_for_server(server_url)
    else:
        analyzer.session.start()

    try:
        yield analyzer
    finally:
        if use_server:
            if server_proc and not persist:
                server_proc.terminate()
                server_proc.wait(timeout=10)
        else:
            analyzer.session.close()


@pytest.fixture(scope="session")
def cpg_path():
    cache_dir = os.path.abspath(".cpg_cache")
    os.makedirs(cache_dir, exist_ok=True)
    parse_timeout = float(os.environ.get("HOPPY_JOERN_PARSE_TIMEOUT", "120"))

    def _cpg_path(src_path: str) -> str:
        abs_src = os.path.abspath(src_path)
        stat = os.stat(abs_src)
        key = f"{abs_src}:{stat.st_mtime_ns}"
        digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
        out = os.path.join(cache_dir, f"{os.path.basename(abs_src)}.{digest}.bin")
        if os.path.exists(out) and os.path.getsize(out) < 20000:
            os.remove(out)
        if not os.path.exists(out):
            try:
                joern_parse_cmd = _get_joern_parse_cmd()
                subprocess.run(
                    [joern_parse_cmd, abs_src, "--output", out],
                    check=True,
                    timeout=parse_timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"joern-parse timed out after {parse_timeout}s for {abs_src}"
                ) from exc
        return out

    return _cpg_path


def _load_cpg_path(analyzer, cpg_path, src_path: str):
    path = cpg_path(src_path)
    if analyzer._current_cpg != path:
        analyzer.load_cpg(path)
        analyzer._current_cpg = path
    return analyzer


@pytest.fixture
def load_cpg(analyzer, cpg_path):
    def _load(src_path: str):
        return _load_cpg_path(analyzer, cpg_path, src_path)

    return _load


@pytest.fixture
def args_cpg(analyzer, cpg_path):
    return _load_cpg_path(analyzer, cpg_path, "./test_app/args_test.py")


@pytest.fixture
def auth_cpg(analyzer, cpg_path):
    return _load_cpg_path(analyzer, cpg_path, "./test_app/auth.py")


@pytest.fixture
def composition_cpg(analyzer, cpg_path):
    return _load_cpg_path(analyzer, cpg_path, "./test_app/composition.py")


@pytest.fixture
def context_cpg(analyzer, cpg_path):
    return _load_cpg_path(analyzer, cpg_path, "./test_app/context.py")


@pytest.fixture
def edge_cases_cpg(analyzer, cpg_path):
    return _load_cpg_path(analyzer, cpg_path, "./test_app/edge_cases.py")


@pytest.fixture
def field_test_cpg(analyzer, cpg_path):
    return _load_cpg_path(analyzer, cpg_path, "./test_app/field_test.py")


@pytest.fixture
def metavars_cpg(analyzer, cpg_path):
    return _load_cpg_path(analyzer, cpg_path, "./test_app/metavars.py")


@pytest.fixture
def sanitizer_cpg(analyzer, cpg_path):
    return _load_cpg_path(analyzer, cpg_path, "./test_app/sanitizer.py")


@pytest.fixture
def snippets_cpg(analyzer, cpg_path):
    return _load_cpg_path(analyzer, cpg_path, "./test_app/snippets.py")


@pytest.fixture
def types_test_cpg(analyzer, cpg_path):
    return _load_cpg_path(analyzer, cpg_path, "./test_app/types_test.py")


@pytest.fixture
def webapp_cpg(analyzer, cpg_path):
    return _load_cpg_path(analyzer, cpg_path, "./test_app/webapp.py")
