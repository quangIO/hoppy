import fnmatch
import os
import re
from dataclasses import dataclass, field

import pathspec
import tiktoken
from rich.console import Console
from rich.status import Status
from rich.tree import Tree

from .analyzer import Analyzer
from .orchestrator import get_endpoints

# Keywords indicating security relevance
SECURITY_KEYWORDS = [
    "auth",
    "login",
    "password",
    "secret",
    "key",
    "token",
    "credential",
    "jwt",
    "oauth",
    "session",
    "cookie",
    "encrypt",
    "decrypt",
    "hash",
    "signature",
    "verify",
    "role",
    "permission",
    "acl",
    "rbac",
    "admin",
    "user",
    "account",
    "profile",
    "registration",
    "signup",
    "signin",
    "logout",
    "database",
    "db",
    "sql",
    "query",
    "exec",
    "shell",
    "system",
    "os",
    "subprocess",
    "command",
    "net",
    "http",
    "request",
    "response",
    "router",
    "route",
    "endpoint",
    "controller",
    "api",
    "middleware",
    "bypass",
    "guard",
    "barrier",
]

# Keywords that indicate auth/permission checks worth surfacing in pack output.
AUTH_GUARD_KEYWORDS = [
    "checkpermission",
    "requireauth",
    "authguard",
    "jwt.verify",
    "validate-request",
    "notauthorized",
    "permissionguard",
]

# Frontend paths to down-rank when scoring for security relevance.
FRONTEND_PATH_HINTS = [
    "frontend/",
    "client/",
    "ui/",
    "web/",
    "public/",
    "static/",
    "assets/",
    "components/",
    "views/",
]

# Backend paths that should not be treated as frontend.
BACKEND_PATH_HINTS = [
    "backend/",
    "server/",
    "api/",
    "routes/",
    "routers/",
    "controllers/",
]

# File patterns that are generally more important
CRITICAL_FILE_PATTERNS = [
    "*auth*",
    "*security*",
    "*config*",
    "*secret*",
    "*key*",
    "*token*",
    "*database*",
    "*db*",
    "*model*",
    "*controller*",
    "*route*",
    "*api*",
    "*endpoint*",
    "*.env*",
    "dockerfile",
    "docker-compose.yml",
    "requirements.txt",
    "pyproject.toml",
    "go.mod",
    "cargo.toml",
    "package.json",
    "composer.json",
    "appsettings.json",
]

# Files and directories to ignore to reduce noise
NOISE_PATTERNS = [
    "*.css",
    "*.svg",
    "*.lock",
    "*.min.js",
    "*.map",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.eot",
    "*test*",
    "*spec*",
    "*mock*",
    "node_modules/",
    "venv/",
    ".venv/",
    "dist/",
    "build/",
    ".git/",
    "__pycache__/",
    ".pytest_cache/",
    ".ruff_cache/",
    ".mypy_cache/",
    ".dccache",
    ".scannerwork/",
    "pnpm-lock.yaml",
    "package-lock.json",
    "yarn.lock",
]


@dataclass
class FileScore:
    path: str
    score: int
    reasons: list[str] = field(default_factory=list)


class RepoPacker:
    def __init__(
        self,
        root_path: str,
        analyzer: Analyzer | None = None,
        language: str | None = None,
        console: Console | None = None,
        call_graph_pattern: str | None = None,
        call_graph_exclude: list[str] | None = None,
    ):
        self.root_path = os.path.abspath(root_path)
        self.analyzer = analyzer
        self.language = language
        self.console = console or Console()
        self.call_graph_pattern = call_graph_pattern
        self.call_graph_exclude = call_graph_exclude or []
        self.ignore_spec = self._load_gitignore()
        self.enc = tiktoken.get_encoding("cl100k_base")
        self._status: Status | None = None

    def _load_gitignore(self) -> pathspec.PathSpec:
        gitignore_path = os.path.join(self.root_path, ".gitignore")
        patterns = []
        if os.path.exists(gitignore_path):
            with open(gitignore_path) as f:
                patterns = f.read().splitlines()

        # Add noise patterns to ignore
        patterns.extend(NOISE_PATTERNS)

        return pathspec.PathSpec.from_lines("gitignore", patterns)

    def _is_ignored(self, file_path: str) -> bool:
        rel_path = os.path.relpath(file_path, self.root_path)
        ignored = self.ignore_spec.match_file(rel_path)
        return ignored

    def _update_status(self, message: str):
        if self._status:
            self._status.update(f"[bold info]{message}[/bold info]")
        else:
            # Fallback if no external status is provided - but we avoid creating many nested ones
            pass

    def _calculate_score(
        self,
        file_path: str,
        content: str,
        dynamic_boosts: dict[str, int],
        dynamic_reasons: dict[str, set[str]],
    ) -> FileScore:
        score = 0
        reasons = []
        rel_path = os.path.relpath(file_path, self.root_path)
        rel_path_norm = rel_path.replace("\\", "/").lower()

        # 1. Critical File Patterns
        for pattern in CRITICAL_FILE_PATTERNS:
            if fnmatch.fnmatch(os.path.basename(file_path).lower(), pattern):
                score += 30
                reasons.append(f"Matches pattern '{pattern}'")
                break

        # 2. Dynamic Analysis Boost (Functional Security Gravity + Scan Rules)
        if rel_path in dynamic_boosts:
            score += dynamic_boosts[rel_path]
            if rel_path in dynamic_reasons:
                reasons.extend(sorted(list(dynamic_reasons[rel_path])))

        # 3. Content Analysis (Keywords)
        content_lower = content.lower()
        keyword_hits = 0
        keyword_occurrences = 0
        for keyword in SECURITY_KEYWORDS:
            occurrences = content_lower.count(keyword)
            if occurrences:
                keyword_hits += 1
                keyword_occurrences += occurrences

        if keyword_hits > 0:
            # Cap keyword score
            k_score = min(keyword_hits * 5, 50)
            score += k_score
            reasons.append(f"Contains {keyword_hits} security keywords")

            repeat_excess = keyword_occurrences - keyword_hits
            if repeat_excess >= 10 and keyword_occurrences >= keyword_hits * 3:
                penalty = min(repeat_excess * 2, 40)
                score -= penalty
                reasons.append(f"Keyword repetition penalty ({repeat_excess} repeats)")

        # 3b. Auth/permission guard boost
        guard_hits = 0
        for keyword in AUTH_GUARD_KEYWORDS:
            if keyword in content_lower:
                guard_hits += 1
        if guard_hits:
            boost = min(guard_hits * 15, 45)
            score += boost
            reasons.append(f"Auth/permission guard signals ({guard_hits})")

        # 4. Frontend penalty (unless path clearly looks backend)
        is_frontend_path = any(hint in rel_path_norm for hint in FRONTEND_PATH_HINTS)
        is_backend_path = any(hint in rel_path_norm for hint in BACKEND_PATH_HINTS)
        if is_frontend_path and not is_backend_path:
            score -= 60
            reasons.append("Frontend code penalty")
        elif os.path.splitext(rel_path_norm)[1] in (".tsx", ".jsx", ".vue", ".svelte"):
            score -= 40
            reasons.append("Frontend file type penalty")

        return FileScore(path=file_path, score=score, reasons=reasons)

    def _get_dynamic_highlights(self) -> tuple[dict[str, int], dict[str, set[str]]]:
        """
        Calculates Security Gravity scores by tracing paths and running scan rules.
        Returns (boosts_dict, reasons_dict).
        """
        if not self.analyzer:
            return {}, {}

        file_boosts = {}
        file_reasons = {}

        def add_boost(rel_path, score, reason):
            if not rel_path or rel_path.startswith(".."):
                return
            file_boosts[rel_path] = max(file_boosts.get(rel_path, 0), score)
            file_reasons.setdefault(rel_path, set()).add(reason)

        try:
            from . import rules

            # 1. Identify Entry Points
            self._update_status("Mapping Attack Surface...")
            endpoints = get_endpoints(self.analyzer, language=self.language, depth=5)
            endpoint_names = [e.fullname for e in endpoints]
            entry_file_pattern = ".*"
            if (self.language or "").lower() == "javascript":
                entry_file_pattern = r".*(/|\\)(routes?|routers?|controllers?|api)(/|\\).*"
                endpoint_names = [
                    name
                    for name in endpoint_names
                    if any(
                        token in name
                        for token in ("/routes/", "/routers/", "/controllers/", "/api/")
                    )
                ]
            entry_res = self.analyzer.list_methods(
                pattern=self.call_graph_pattern or ".*",
                entry_points_only=True,
                internal_only=True,
                file_pattern=entry_file_pattern,
            ).unwrap()
            if not entry_res and entry_file_pattern != ".*":
                entry_res = self.analyzer.list_methods(
                    pattern=self.call_graph_pattern or ".*",
                    entry_points_only=True,
                    internal_only=True,
                    file_pattern=r".*(/|\\)backend(/|\\).*",
                ).unwrap()
            all_starts = list(set(endpoint_names + (entry_res or [])))
            if self.call_graph_pattern:
                try:
                    pattern_re = re.compile(self.call_graph_pattern)
                    all_starts = [s for s in all_starts if pattern_re.search(s)]
                except re.error:
                    pass

            # 2. Structural Security Gravity (Call Graph to Sinks)
            if all_starts:
                self._update_status("Tracing paths to security sinks...")
                heuristics = rules.get_discovery_heuristics(self.language)

                def chunked(seq, size):
                    for i in range(0, len(seq), size):
                        yield seq[i : i + size]

                trees = []
                # Chunk to avoid oversized Scala payloads for large repos.
                for batch in chunked(all_starts, 20):
                    batch_trees = self.analyzer.get_call_graph(
                        batch,
                        direction="callee",
                        depth=12,
                        exclude_patterns=self.call_graph_exclude,
                        heuristics=heuristics,
                        interesting_only=True,
                    ).unwrap()
                    trees.extend(batch_trees)

                def traverse(node):
                    category = node.get("category")
                    f = node.get("file")

                    # Recursively get min depth from children (closest sink)
                    min_child_depth = 99
                    for child in node.get("children", []):
                        d = traverse(child)
                        min_child_depth = min(min_child_depth, d)

                    # Current node's distance to nearest sink
                    current_depth_from_sink = 0 if category else (min_child_depth + 1)

                    # Calculate boost based on distance
                    if category:
                        node_boost = 150
                        reason = f"Security Sink ({category})"
                    elif current_depth_from_sink < 5:
                        node_boost = 120 - (current_depth_from_sink * 20)
                        reason = f"Security Gravity (dist {current_depth_from_sink} to sink)"
                    else:
                        node_boost = 40
                        reason = "Path to security sink"

                    if f and f != "<empty>" and f != "external":
                        try:
                            # Joern paths are often relative to project root
                            abs_f = os.path.join(self.root_path, f) if not os.path.isabs(f) else f
                            rel = os.path.relpath(abs_f, self.root_path)
                            add_boost(rel, node_boost, reason)
                        except Exception:
                            pass

                    # Also check callerFile if available (useful for some Joern frontends)
                    cf = node.get("callerFile")
                    if cf and cf != "<empty>" and cf != "external":
                        try:
                            abs_cf = (
                                os.path.join(self.root_path, cf) if not os.path.isabs(cf) else cf
                            )
                            rel_cf = os.path.relpath(abs_cf, self.root_path)
                            add_boost(rel_cf, node_boost // 2, f"Caller of {reason}")
                        except Exception:
                            pass

                    return current_depth_from_sink

                for tree in trees:
                    traverse(tree)

            # 3. Deep Vulnerability Scanning (Source-to-Sink Data Flow)
            self._update_status("Running security scan rules...")
            scan_rules = rules.get_scan_rules(self.language)
            for rule in scan_rules:
                matches = self.analyzer.execute(rule.query).unwrap()
                for match in matches:
                    # Boost the entire data flow path
                    for element in match.flow:
                        if element.file:
                            try:
                                abs_path = (
                                    os.path.join(self.root_path, element.file)
                                    if not os.path.isabs(element.file)
                                    else element.file
                                )
                                rel = os.path.relpath(abs_path, self.root_path)
                                add_boost(rel, 100, f"Vulnerability flow ({rule.name})")
                            except Exception:
                                pass

                    # Extra boost for the sink file itself
                    if match.file:
                        try:
                            abs_path = (
                                os.path.join(self.root_path, match.file)
                                if not os.path.isabs(match.file)
                                else match.file
                            )
                            rel = os.path.relpath(abs_path, self.root_path)
                            add_boost(rel, 100, f"Vulnerability sink ({rule.name})")
                        except Exception:
                            pass

            # 4. Custom Wrappers boost
            try:
                heuristics = rules.get_discovery_heuristics(self.language)
                wrappers = self.analyzer.discover_wrappers(heuristics).unwrap()
                for w in wrappers:
                    if "file" in w:
                        try:
                            abs_path = (
                                os.path.join(self.root_path, w["file"])
                                if not os.path.isabs(w["file"])
                                else w["file"]
                            )
                            rel = os.path.relpath(abs_path, self.root_path)
                            add_boost(rel, 80, "Potential Custom Sink/Wrapper")
                        except Exception:
                            pass
            except Exception:
                pass

        except Exception as e:
            import traceback

            self.console.print(
                f"[yellow]Warning: Failed to complete dynamic analysis: {e}[/yellow]"
            )
            if self.analyzer and self.analyzer.verbose:
                self.console.print(traceback.format_exc())

        return file_boosts, file_reasons

    def generate_tree(self, files: list[str]) -> str:
        """Generates an ASCII tree of the included files."""
        tree = Tree("[bold]Repository Structure[/bold]")
        file_list = sorted(files)

        # Build nested dictionary
        structure = {}
        for path in file_list:
            parts = path.split(os.sep)
            current = structure
            for part in parts:
                current = current.setdefault(part, {})

        def add_to_tree(node, current_struct):
            for name, substruct in current_struct.items():
                if not substruct:  # It's a file
                    node.add(name)
                else:  # It's a directory
                    sub_node = node.add(f"[bold cyan]{name}/[/bold cyan]")
                    add_to_tree(sub_node, substruct)

        add_to_tree(tree, structure)

        # Capture rich output to string
        import io

        from rich.console import Console

        buf = io.StringIO()
        c = Console(file=buf, force_terminal=False, width=80)
        c.print(tree)
        return buf.getvalue()

    def pack(
        self,
        max_tokens: int = 100000,
        exclude_files: list[str] | None = None,
        status: Status | None = None,
    ) -> str:
        self._status = status
        dynamic_boosts, dynamic_reasons = self._get_dynamic_highlights()

        scored_files = []
        all_files = []
        exclude_set = set(exclude_files or [])

        self._update_status("Scanning files and calculating scores...")
        for root, dirs, files in os.walk(self.root_path):
            # Modify dirs in-place to respect gitignore (append / for directory matching)
            dirs[:] = [d for d in dirs if not self._is_ignored(os.path.join(root, d) + os.sep)]

            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.root_path)

                if self._is_ignored(file_path) or rel_path in exclude_set:
                    continue

                try:
                    # Skip non-text files
                    with open(file_path, encoding="utf-8") as f:
                        content = f.read()
                except (UnicodeDecodeError, PermissionError):
                    continue
                except Exception:
                    continue

                score_data = self._calculate_score(
                    file_path, content, dynamic_boosts, dynamic_reasons
                )
                scored_files.append((score_data, content, rel_path))
                all_files.append(rel_path)

        # Sort by score descending
        scored_files.sort(key=lambda x: x[0].score, reverse=True)

        # Generate Tree
        tree_str = self.generate_tree(all_files)
        tree_tokens = len(self.enc.encode(tree_str))

        output_buffer = [tree_str, "\n"]
        current_tokens = tree_tokens

        included_files = []
        show_reasons = os.getenv("HOPPY_PACK_REASONS") == "1"

        for score_data, content, rel_path in scored_files:
            # Format: >>>> path/to/file (Score: X, Reasons: Y)
            if show_reasons:
                reason_str = ", ".join(score_data.reasons)
                header = f">>>> {rel_path} (Score: {score_data.score}, Reasons: {reason_str})\n"
            else:
                header = f">>>> {rel_path} (Score: {score_data.score})\n"
            file_entry = f"{header}{content}\n"
            entry_tokens = len(self.enc.encode(file_entry))

            if current_tokens + entry_tokens > max_tokens:
                break

            output_buffer.append(file_entry)
            current_tokens += entry_tokens
            included_files.append(f"{rel_path} (Score: {score_data.score})")

        self.console.print(
            f"[bold success]Packed {len(included_files)} files "
            f"({current_tokens} tokens).[/bold success]"
        )
        return "".join(output_buffer)
