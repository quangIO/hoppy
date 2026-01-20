import json
import os
import re
from typing import Any

from rich.columns import Columns
from rich.console import Console, Group
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.tree import Tree

from . import sarif as om
from .core.match import Match
from .core.rule import ScanRule, Severity
from .core.slicing import Slice, SliceNode

__all__ = [
    "custom_theme",
    "ConsoleReporter",
    "SarifReporter",
    "SliceReporter",
    "UsageSliceReporter",
]

# Custom theme for security findings
custom_theme = Theme(
    {
        "info": "cyan",
        "low": "green",
        "medium": "yellow",
        "high": "bold red",
        "critical": "bold white on red",
        "success": "bold green",
        "location": "bright_blue",
        "method": "italic magenta",
        "code": "green",
        "tainted": "bold red underline",
        "step_header": "bold white on blue",
    }
)

SEVERITY_STYLE = {
    "info": "cyan",
    "low": "green",
    "medium": "bold yellow",
    "high": "bold red",
    "critical": "bold white on red",
}

CONFIDENCE_STYLE = {
    "low": "dim",
    "medium": "white",
    "high": "bold white",
}

CONFIDENCE_SYMBOLS = {
    "low": "●○○",
    "medium": "●●○",
    "high": "●●●",
}

HEADER_STYLE = {
    "info": "white on blue",
    "low": "white on green",
    "medium": "black on yellow",
    "high": "white on red",
    "critical": "white on red",
}

STOPWORDS = {"new", "var", "this"}


def normalize_step_code(code: str) -> str:
    clean_code = code.strip()
    # Remove Joern operators if present
    if clean_code.startswith("<operator>."):
        clean_code = clean_code.split(".", 1)[1]
        if "(" in clean_code and clean_code.endswith(")"):
            # Extract content between first ( and last )
            clean_code = clean_code[clean_code.find("(") + 1 : clean_code.rfind(")")]

    if "):" in clean_code:
        clean_code = clean_code.split("):", 1)[1].strip()
    if ":" in clean_code and "(" in clean_code and clean_code.rfind(":") > clean_code.rfind(")"):
        clean_code = clean_code.rsplit(":", 1)[1]
    return clean_code.strip()


def build_candidates(clean_code: str) -> list[str]:
    seen = set()
    candidates = []
    if clean_code:
        candidates.append(clean_code)

    # If it's a comma-separated list (from operators), add individual parts
    if "," in clean_code:
        for part in clean_code.split(","):
            p = part.strip().strip("'\"`")
            if p:
                candidates.append(p)

    if "=" in clean_code:
        rhs = clean_code.split("=", 1)[1].strip()
        if rhs:
            candidates.append(rhs)

    # Add call-like and identifier-like spans
    for match in re.findall(r"[A-Za-z_][\w.]*\s*\([^)]*\)", clean_code):
        candidates.append(match)
    for match in re.findall(r"[A-Za-z_][\w.]*", clean_code):
        candidates.append(match)

    # Keywords to avoid as candidates unless they are the full code
    keywords = {
        "SELECT",
        "FROM",
        "WHERE",
        "AND",
        "OR",
        "LIKE",
        "ORDER",
        "BY",
        "LIMIT",
        "INSERT",
        "INTO",
        "VALUES",
        "UPDATE",
        "SET",
        "DELETE",
        "NULL",
        "IS",
        "public",
        "private",
        "static",
        "return",
        "class",
        "void",
        "String",
        "int",
    }

    ordered = []
    for candidate in candidates:
        key = candidate.strip()
        if not key:
            continue
        if len(key) < 3:
            continue
        if key.upper() in keywords and len(key) < len(clean_code):
            continue
        if key in seen:
            continue
        seen.add(key)
        ordered.append(key)

    return sorted(ordered, key=lambda c: (-len(c), ordered.index(c)))


def _lexer_for_path(path):
    if path.endswith(".py"):
        return "python"
    if path.endswith(".js"):
        return "javascript"
    if path.endswith(".java"):
        return "java"
    return "csharp"


def resolve_file_path(base_path: str, rel_path: str) -> str | None:
    if not rel_path:
        return None
    abs_path = rel_path if os.path.isabs(rel_path) else os.path.join(base_path, rel_path)
    if os.path.exists(abs_path):
        return abs_path

    # Try finding the file by just its name in base_path if joined path doesn't exist
    fname = rel_path.split("/")[-1] if "/" in rel_path else rel_path
    for root, _, files in os.walk(base_path):
        if fname in files:
            return os.path.join(root, fname)
    return None


def resolve_region(
    file_path: str | None,
    line_num: int | None,
    col_num: int | None,
    code: str | None,
) -> tuple[int, int, int | None, int | None]:
    """
    Fuzzy matches code in file to find best start/end line and column.
    Returns (startLine, startColumn, endLine, endColumn)
    """
    if not file_path or not os.path.exists(file_path):
        return (line_num or 1, col_num or 1, None, None)

    try:
        with open(file_path, encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return (line_num or 1, col_num or 1, None, None)

    clean_target = normalize_step_code(code) if code else None
    if not clean_target:
        return (line_num or 1, col_num or 1, None, None)

    reported_line_idx = (line_num - 1) if line_num else 0
    actual_line_idx = reported_line_idx
    actual_col = col_num

    # Fuzzy Line Match
    found = False
    if 0 <= reported_line_idx < len(lines) and clean_target in lines[reported_line_idx]:
        found = True
    else:
        for offset in [1, -1, 2, -2]:
            check_idx = reported_line_idx + offset
            if 0 <= check_idx < len(lines) and clean_target in lines[check_idx]:
                actual_line_idx = check_idx
                actual_col = None  # Column is likely wrong if line is wrong
                found = True
                break

    if not found:
        # Last resort: search entire file for first occurrence
        for idx, line_text in enumerate(lines):
            if clean_target in line_text:
                actual_line_idx = idx
                actual_col = None
                found = True
                break

    if found:
        line_text = lines[actual_line_idx]
        if actual_col is not None and actual_col > 0:
            start_pos = actual_col - 1
            # Verify if target is actually at reported column
            if (
                clean_target
                and line_text[start_pos : start_pos + len(clean_target)] != clean_target
            ):
                actual_col = line_text.find(clean_target) + 1
        else:
            actual_col = line_text.find(clean_target) + 1

        if actual_col > 0:
            return (
                actual_line_idx + 1,
                actual_col,
                actual_line_idx + 1,
                actual_col + len(clean_target),
            )

    return (actual_line_idx + 1, actual_col or 1, None, None)


class Reporter:
    def report(self, *args, **kwargs):
        raise NotImplementedError

    def finalize(self):
        pass


class ConsoleReporter(Reporter):
    def __init__(
        self,
        console: Console | None = None,
        base_path: str = "",
        max_findings: int = 3,
    ):
        self.console = console or Console(theme=custom_theme)
        self.base_path = base_path
        self.max_findings = max_findings
        self._summary_total = 0
        self._summary_rules: dict[str, int] = {}
        self._summary_rule_severity: dict[str, str] = {}
        self._summary_severity: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        self._summary_files: set[str] = set()
        self._displayed_metadata: set[str] = set()

    def get_source_context(
        self, rel_path, line_num, tainted_code=None, col_num=None, context_lines=1
    ):
        """Reads source context with column highlighting and fuzzy fallback."""
        actual_line_val = line_num
        actual_col_val = col_num

        abs_path = resolve_file_path(self.base_path, rel_path)
        if not abs_path:
            return None

        start_line, start_col, _, _ = resolve_region(
            abs_path, actual_line_val, actual_col_val, tainted_code
        )

        try:
            with open(abs_path, encoding="utf-8") as f:
                lines = f.readlines()

            line_idx = start_line - 1
            start = max(0, line_idx - context_lines)
            end = min(len(lines), line_idx + context_lines + 1)
            lexer = _lexer_for_path(abs_path)

            clean_target = normalize_step_code(tainted_code or "")

            temp_console = Console(width=1000, force_terminal=True)
            final_lines = []
            for i in range(start, end):
                curr_line = i + 1
                raw_line = lines[i].rstrip()
                line_syntax = Syntax(raw_line, lexer, theme="monokai", background_color="default")
                segments = temp_console.render_lines(line_syntax, temp_console.options)[0]
                line_text = Text()
                for seg in segments:
                    line_text.append(seg.text, style=seg.style)

                prefix = Text(f" {curr_line:4} ")
                if i == line_idx:
                    prefix.append("❱ ", style="bold red")
                    start_pos = start_col - 1
                    if (
                        clean_target
                        and line_text.plain[start_pos : start_pos + len(clean_target)]
                        == clean_target
                    ):
                        line_text.stylize("tainted", start_pos, start_pos + len(clean_target))
                    elif clean_target:
                        start_pos = line_text.plain.find(clean_target)
                        if start_pos != -1:
                            line_text.stylize("tainted", start_pos, start_pos + len(clean_target))
                    else:
                        line_text.stylize("tainted", start_pos, start_pos + 1)
                else:
                    prefix.append("  ", style="dim")
                    prefix.stylize("dim", 0, 5)
                final_lines.append(prefix + line_text)
            return Group(*final_lines)
        except Exception:
            return None

    def get_merged_context(self, full_path, steps, context_lines=1):
        """Merges consecutive steps within 10 lines into a single code block
        with labeled highlights."""
        if not steps:
            return None

        abs_path = resolve_file_path(self.base_path, full_path)
        if not abs_path:
            return None

        try:
            with open(abs_path, encoding="utf-8") as f:
                lines = f.readlines()

            lexer = _lexer_for_path(abs_path)

            def _find_best_line(step, search_lines, start_idx=0, end_idx=None, base_idx=0):
                end_idx = end_idx if end_idx is not None else len(search_lines)
                clean_code = normalize_step_code(step["code"])
                candidates = build_candidates(clean_code)
                best = None
                best_len = 0
                best_dist = None
                for idx in range(start_idx, end_idx):
                    line_text = search_lines[idx]
                    for candidate in candidates:
                        if candidate in line_text:
                            cand_len = len(candidate)
                            dist = abs(idx - base_idx)
                            if (
                                best is None
                                or cand_len > best_len
                                or (cand_len == best_len and dist < best_dist)
                            ):
                                best = idx
                                best_len = cand_len
                                best_dist = dist
                            break
                return best

            line_to_steps = {}
            for step in steps:
                line_num = None
                if step["line"] and str(step["line"]).isdigit():
                    line_num = int(step["line"])
                if line_num is not None:
                    base_idx = max(0, line_num - 1)
                    start_idx = max(0, base_idx - 2)
                    end_idx = min(len(lines), base_idx + 3)
                    best_idx = _find_best_line(step, lines, start_idx, end_idx, base_idx=base_idx)
                    if best_idx is not None:
                        line_num = best_idx + 1
                else:
                    best_idx = _find_best_line(step, lines, 0, len(lines), base_idx=0)
                    if best_idx is not None:
                        line_num = best_idx + 1
                if line_num is None:
                    continue
                step["display_line"] = str(line_num)
                if line_num not in line_to_steps:
                    line_to_steps[line_num] = []
                line_to_steps[line_num].append(step)

            if not line_to_steps:
                return None

            sorted_lines = sorted(line_to_steps.keys())
            line_ranges = []
            current_range = [sorted_lines[0]]

            for i in range(1, len(sorted_lines)):
                if sorted_lines[i] - sorted_lines[i - 1] <= 10:
                    current_range.append(sorted_lines[i])
                else:
                    line_ranges.append((min(current_range), max(current_range)))
                    current_range = [sorted_lines[i]]

            if current_range:
                line_ranges.append((min(current_range), max(current_range)))

            renderables = []
            for range_idx, (range_start, range_end) in enumerate(line_ranges):
                start = max(0, range_start - context_lines - 1)
                end = min(len(lines), range_end + context_lines)

                block_steps = []
                for line_num in range(range_start, range_end + 1):
                    if line_num in line_to_steps:
                        block_steps.extend(line_to_steps[line_num])

                def _get_label_text(step):
                    lbl = step["label"]
                    return lbl if lbl == "SINK" else f"S{lbl}"

                def _label_sort_key(step):
                    lbl = step["label"]
                    if lbl == "SINK":
                        return 999999
                    try:
                        return int(lbl)
                    except ValueError:
                        return 0

                label_strings = {}
                max_label_len = 0
                for line_num in range(range_start, range_end + 1):
                    if line_num in line_to_steps:
                        labels = ",".join(
                            _get_label_text(s)
                            for s in sorted(line_to_steps[line_num], key=_label_sort_key)
                        )
                        label_strings[line_num] = labels
                        max_label_len = max(max_label_len, len(labels))

                final_lines = []
                temp_console = Console(width=1000, force_terminal=True)
                for i in range(start, end):
                    curr_line = i + 1
                    raw_line = lines[i].rstrip()
                    line_syntax = Syntax(
                        raw_line, lexer, theme="monokai", background_color="default"
                    )
                    segments = temp_console.render_lines(line_syntax, temp_console.options)[0]
                    line_text = Text()
                    for seg in segments:
                        line_text.append(seg.text, style=seg.style)

                    prefix = Text(f" {curr_line:4} ")
                    label = label_strings.get(curr_line, "")
                    continuation_label = ""
                    if not label:
                        prev_label = label_strings.get(curr_line - 1, "")
                        if prev_label and raw_line.lstrip().startswith("."):
                            continuation_label = prev_label

                    if label:
                        prefix.append("❱ ", style="bold red")
                        prefix.append(label.ljust(max_label_len), style="bold red")
                    elif continuation_label:
                        prefix.append("↳ ", style="bold red")
                        prefix.append(continuation_label.ljust(max_label_len), style="bold red")
                    else:
                        prefix.append("  ", style="dim")
                        prefix.append(" " * max_label_len, style="dim")
                        prefix.stylize("dim", 0, 5)
                    prefix.append(" ")

                    steps_for_highlight = None
                    if curr_line in line_to_steps:
                        steps_for_highlight = line_to_steps[curr_line]
                    elif continuation_label:
                        steps_for_highlight = line_to_steps.get(curr_line - 1)

                    if steps_for_highlight:
                        all_matches = []
                        for step in steps_for_highlight:
                            clean_code = normalize_step_code(step["code"])
                            if ":" in clean_code and "(" not in clean_code[: clean_code.find(":")]:
                                clean_code = clean_code.split(":")[-1].strip()

                            candidates = build_candidates(clean_code)

                            step_matches = []
                            # Quote-agnostic line text for searching
                            search_line = line_text.plain.replace("`", '"').replace("'", '"')

                            for candidate in candidates:
                                # Quote-agnostic candidate
                                search_cand = candidate.replace("`", '"').replace("'", '"')

                                start_search = 0
                                found_any = False
                                while True:
                                    idx = search_line.find(search_cand, start_search)
                                    if idx == -1:
                                        break
                                    step_matches.append((idx, idx + len(candidate)))
                                    start_search = idx + 1
                                    found_any = True

                                if found_any:
                                    # Found best candidate, stop looking for others for this step
                                    break

                            if step_matches:
                                all_matches.extend(step_matches)

                        if all_matches:
                            # Sort by length (descending) and then by start position
                            all_matches.sort(key=lambda m: (-(m[1] - m[0]), m[0]))
                            selected = []
                            for start_pos, end_pos in all_matches:
                                if any(
                                    start_pos < s_end and end_pos > s_start
                                    for s_start, s_end in selected
                                ):
                                    continue
                                selected.append((start_pos, end_pos))

                            for h_start, h_end in selected:
                                line_text.stylize("tainted", h_start, h_end)
                    final_lines.append(prefix + line_text)

                if final_lines:
                    renderables.append(Group(*final_lines))
                    if range_idx < len(line_ranges) - 1:
                        renderables.append("")
            return Group(*renderables) if renderables else None
        except Exception:
            return None

    def _render_match(self, rule: ScanRule, match: Match):
        line_display = str(match.line) if match.line is not None else "?"
        head_style = HEADER_STYLE.get(rule.severity_name, "white on red")
        conf_sym = CONFIDENCE_SYMBOLS.get(rule.confidence_name, "●●●")

        header_text = Text()
        # Only the name gets the background
        header_text.append(f"{rule.name.upper()} ", style=f"bold {head_style}")

        # Rest of the header is standard
        header_text.append(" ")
        for char in conf_sym:
            if char == "●":
                header_text.append(char, style="bold")
            else:
                header_text.append(char, style="dim")
        header_text.append(" ")

        header_text.append(f" {match.file}:{line_display} ", style="location")

        renderables = []

        summary = Table.grid(padding=(0, 1))
        summary.add_column(style="bold", width=12)
        summary.add_column()
        summary.add_row("Sink Code", Text(match.code.strip(), style="dim"))
        if match.bindings:
            clean_bindings = {k: v for k, v in match.bindings.items() if not k.startswith("$.")}
            if clean_bindings:
                bind_str = ", ".join([f"{k}={v}" for k, v in clean_bindings.items()])
                summary.add_row("Bindings", Text(bind_str, style="dim"))

        renderables.append(summary)
        renderables.append("")

        if match.flow:
            # 1. Collect all steps including Sink
            all_steps = []
            for step_model in match.flow:
                full_path = step_model.file
                line = str(step_model.line) if step_model.line is not None else ""
                method = step_model.method
                code = step_model.code
                if method:
                    method = method.split(".")[-1].split(":")[0]

                all_steps.append(
                    {
                        "full_path": resolve_file_path(self.base_path, full_path) or full_path,
                        "line": line,
                        "method": method,
                        "code": normalize_step_code(code),
                        "is_sink": False,
                    }
                )

            sink_path = resolve_file_path(self.base_path, match.file) or match.file
            sink_line = str(match.line) if match.line is not None else ""
            sink_code = normalize_step_code(match.code)

            # Add Sink if not already the last step
            is_same = (
                all_steps
                and all_steps[-1]["line"] == sink_line
                and all_steps[-1]["code"] == sink_code
            )
            if not all_steps or not is_same:
                all_steps.append(
                    {
                        "full_path": sink_path,
                        "line": sink_line,
                        "method": match.method_fullname.split("(")[0].split(".")[-1],
                        "code": sink_code,
                        "is_sink": True,
                    }
                )
            else:
                all_steps[-1]["is_sink"] = True

            # 2. Deduplicate: keep only the longest pattern per file/line
            deduped_steps = []
            seen_locations = {}  # (path, line) -> index in deduped_steps

            for step in all_steps:
                loc = (step["full_path"], step["line"])
                if loc[1]:  # Only dedup if we have a line number
                    if loc in seen_locations:
                        idx = seen_locations[loc]
                        if len(step["code"]) > len(deduped_steps[idx]["code"]):
                            # Preserve sink status if either was a sink
                            was_sink = deduped_steps[idx]["is_sink"] or step["is_sink"]
                            deduped_steps[idx] = step
                            deduped_steps[idx]["is_sink"] = was_sink
                        continue
                    seen_locations[loc] = len(deduped_steps)
                deduped_steps.append(step)

            # 3. Assign sequential labels
            label_count = 1
            for step in deduped_steps:
                if step["is_sink"]:
                    step["label"] = "SINK"
                else:
                    step["label"] = str(label_count)
                    label_count += 1

            # 4. Group by file but PRESERVE ORDER of first appearance
            file_order = []
            file_groups = {}
            for step in deduped_steps:
                path = step["full_path"]
                if path not in file_groups:
                    file_order.append(path)
                    fname = path.split("/")[-1] if "/" in path else path
                    file_groups[path] = {"fname": fname, "steps": []}
                file_groups[path]["steps"].append(step)

            for path in file_order:
                group = file_groups[path]
                merged_context = self.get_merged_context(path, group["steps"], context_lines=2)
                if merged_context:
                    file_title = Text.assemble(
                        (f" {group['fname']} ", "bold cyan"),
                    )
                    renderables.append(file_title)
                    renderables.append(merged_context)
                    renderables.append("")
        else:
            context = self.get_source_context(
                match.file,
                match.line,
                tainted_code=match.code,
                col_num=match.column,
            )
            if context:
                renderables.append(context)

        self.console.print(header_text)
        self.console.print(Group(*renderables))
        self.console.print("")

    def report(self, rule: ScanRule, matches: list[Match]):
        # Group matches by resolved (sink_file, sink_line, source_file, source_line)
        # to avoid redundant reports while still allowing unique paths from different sources.
        deduped_matches = []
        seen_paths = set()

        for match in sorted(matches, key=lambda m: len(m.code), reverse=True):
            sink_path = resolve_file_path(self.base_path, match.file)
            if not sink_path and match.flow:
                for step in reversed(match.flow):
                    sink_path = resolve_file_path(self.base_path, step.file)
                    if sink_path:
                        break
            if not sink_path:
                sink_path = match.file
            sink_line = match.line or 0

            source_sig = ("unknown", 0)
            if match.flow:
                first_step = match.flow[0]
                source_path = resolve_file_path(self.base_path, first_step.file) or first_step.file
                source_line = first_step.line or 0
                source_sig = (source_path, source_line)

            full_sig = (sink_path, sink_line, source_sig[0], source_sig[1])
            if full_sig in seen_paths:
                continue
            seen_paths.add(full_sig)
            deduped_matches.append(match)

        if deduped_matches:
            self._summary_total += len(deduped_matches)
            self._summary_rules[rule.name] = self._summary_rules.get(rule.name, 0) + len(
                deduped_matches
            )
            self._summary_rule_severity[rule.name] = rule.severity_name
            sev_key = rule.severity_name
            if sev_key in self._summary_severity:
                self._summary_severity[sev_key] += len(deduped_matches)
            else:
                self._summary_severity[sev_key] = len(deduped_matches)
            for match in deduped_matches:
                resolved = resolve_file_path(self.base_path, match.file)
                self._summary_files.add(resolved or match.file)

            # Display metadata once per rule
            if rule.name not in self._displayed_metadata and (rule.root_cause or rule.impact):
                metadata_table = Table.grid(padding=(0, 1))
                metadata_table.add_column(style="bold", width=12)
                metadata_table.add_column()
                if rule.root_cause:
                    metadata_table.add_row("Root Cause", Text(rule.root_cause, style="dim"))
                if rule.impact:
                    metadata_table.add_row("Impact", Text(rule.impact, style="dim"))
                self.console.print(metadata_table)
                self.console.print("")
                self._displayed_metadata.add(rule.name)

        # Group matches by file for reporting limits
        matches_by_file: dict[str, list[Match]] = {}
        for match in deduped_matches:
            resolved = resolve_file_path(self.base_path, match.file)
            file_key = resolved or match.file
            if file_key not in matches_by_file:
                matches_by_file[file_key] = []
            matches_by_file[file_key].append(match)

        # Sort files for deterministic output
        sorted_files = sorted(matches_by_file.keys())

        for file_key in sorted_files:
            file_matches = matches_by_file[file_key]
            # Ensure matches are sorted by code length as per original logic
            file_matches.sort(key=lambda m: len(m.code), reverse=True)

            visible_matches = file_matches
            hidden_count = 0
            if len(file_matches) > self.max_findings:
                visible_matches = file_matches[: self.max_findings]
                hidden_count = len(file_matches) - self.max_findings

            for match in visible_matches:
                self._render_match(rule, match)

            if hidden_count > 0:
                self.console.print(
                    f"[dim]... and {hidden_count} other potential {rule.name} "
                    "findings in this file.[/dim]"
                )
                self.console.print("")

    def finalize(self):
        self.console.print(Rule("[bold cyan]Executive Summary[/bold cyan]", style="cyan"))

        # Overview table - Minimalist
        overview = Table(show_header=False, box=None, padding=(0, 2))
        overview.add_column(style="cyan")
        overview.add_column(justify="right")
        overview.add_row("Findings", Text(str(self._summary_total), style="bold yellow"))
        overview.add_row("Rules hit", Text(str(len(self._summary_rules)), style="bold cyan"))
        overview.add_row("Files affected", Text(str(len(self._summary_files)), style="bold green"))

        # Severity table - Minimalist
        sev_table = Table(show_header=False, box=None, padding=(0, 2))
        sev_table.add_column(style="cyan")
        sev_table.add_column(justify="right")
        for key in ["critical", "high", "medium", "low", "info"]:
            count = self._summary_severity.get(key, 0)
            if count == 0:
                continue
            sev_style = SEVERITY_STYLE.get(key, "white").replace("bold ", "")
            sev_table.add_row(
                Text(key.capitalize(), style=sev_style),
                Text(str(count), style=f"bold {sev_style}"),
            )

        # Display side-by-side
        self.console.print(Columns([overview, sev_table], expand=False))

        # Rules Breakdown
        if self._summary_rules:
            self.console.print("")
            rule_table = Table(show_header=False, box=None, padding=(0, 2))
            rule_table.add_column()
            rule_table.add_column(justify="right")

            for rule_name, count in sorted(
                self._summary_rules.items(), key=lambda item: (-item[1], item[0])
            ):
                sev_key = self._summary_rule_severity.get(rule_name, "info")
                sev_style = SEVERITY_STYLE.get(sev_key, "white").replace("bold ", "")

                rule_text = Text(rule_name, style=sev_style)
                count_text = Text(str(count), style=f"bold {sev_style}")

                rule_table.add_row(rule_text, count_text)

            self.console.print(rule_table)


class SliceReporter(Reporter):
    def __init__(
        self,
        console: Console | None = None,
        max_sinks: int = 10,
        max_paths: int = 10,
        max_depth: int = 25,
        show_paths: bool = True,
        show_evidence: bool = True,
    ):
        self.console = console or Console(theme=custom_theme)
        self.max_sinks = max_sinks
        self.max_paths = max_paths
        self.max_depth = max_depth
        self.show_paths = show_paths
        self.show_evidence = show_evidence

    def report(self, slice_obj: Slice):
        nodes = {n.id: n for n in slice_obj.nodes}
        if not nodes:
            self.console.print("[yellow]Empty slice.[/yellow]")
            return

        in_degree = {n_id: 0 for n_id in nodes}
        out_degree = {n_id: 0 for n_id in nodes}
        for edge in slice_obj.edges:
            if edge.src in nodes and edge.dst in nodes:
                out_degree[edge.src] += 1
                in_degree[edge.dst] += 1

        sinks: list[int] = slice_obj.sinkIds or [
            n_id for n_id, deg in out_degree.items() if deg == 0
        ]
        sources = {n_id for n_id, deg in in_degree.items() if deg == 0}
        origin_ids = slice_obj.originIds or []
        if slice_obj.paramUsageIds:
            origin_ids = list({*origin_ids, *slice_obj.paramUsageIds})

        if not sinks:
            self.console.print("[yellow]No sinks found (cyclic graph?).[/yellow]")
            return

        rev_adj = {n_id: [] for n_id in nodes}
        for edge in slice_obj.edges:
            if edge.src in nodes and edge.dst in nodes:
                rev_adj[edge.dst].append(edge)

        def compact_path(path_ids: list[int]) -> list[int]:
            if not path_ids:
                return []

            def group_key(n: SliceNode) -> tuple[str, int | None, str]:
                return (n.parentFile or "", n.lineNumber, short_method(n.parentMethod))

            def node_key(n: SliceNode) -> tuple[str, int | None, str]:
                code = normalize_step_code(n.code) if n.code else ""
                name = n.name or n.label or ""
                return (n.parentFile or "", n.lineNumber, code or name)

            compacted: list[int] = []
            current_group = group_key(nodes[path_ids[0]])
            current_ids: list[int] = []

            def flush_group(ids: list[int]) -> None:
                if not ids:
                    return
                # Map each node_id to its original index for sorting
                original_order = {n_id: i for i, n_id in enumerate(path_ids)}

                # Sort by code length descending to find "container" nodes
                # We prioritize nodes that fully contain others
                sorted_by_len = sorted(
                    ids,
                    key=lambda n_id: len(normalize_step_code(nodes[n_id].code) or ""),
                    reverse=True,
                )

                kept_ids = []
                for n_id in sorted_by_len:
                    n_code = (normalize_step_code(nodes[n_id].code) or "").strip()
                    if not n_code:
                        continue

                    is_redundant = False
                    for k_id in kept_ids:
                        k_code = (normalize_step_code(nodes[k_id].code) or "").strip()
                        # If current code is a sub-string of an already kept larger code,
                        # it's likely redundant
                        if n_code in k_code and n_code != k_code:
                            is_redundant = True
                            break
                    if not is_redundant:
                        kept_ids.append(n_id)

                # Sort kept_ids back to original relative order
                kept_ids.sort(key=lambda n_id: original_order[n_id])
                compacted.extend(kept_ids)

            for node_id in path_ids:
                node = nodes[node_id]
                gk = group_key(node)
                if gk != current_group and current_ids:
                    flush_group(current_ids)
                    current_ids = []
                    current_group = gk
                current_ids.append(node_id)
            flush_group(current_ids)

            deduped: list[int] = []
            seen = set()
            for node_id in compacted:
                key = node_key(nodes[node_id])
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(node_id)
            return deduped

        def short_method(full: str) -> str:
            if not full:
                return ""
            base = full.split("(", 1)[0]
            if ":" in base and "::" not in base:
                base = base.split(":")[0]
            return base.split(".")[-1].split("::")[-1]

        def is_parameter_node(n: SliceNode) -> bool:
            label = (n.label or "").upper()
            if label in {"METHOD_PARAMETER_IN", "METHOD_PARAMETER_OUT", "PARAMETER"}:
                return True
            name = (n.name or "").lower()
            type_name = (n.typeFullName or "").lower()
            return "parameter" in type_name or name.startswith("param")

        def is_assignment_node(n: SliceNode) -> bool:
            code = normalize_step_code(n.code) if n.code else ""
            if "=" not in code:
                return False
            # Avoid operators like "==" or "!=" or ">=" in conditionals.
            return not any(op in code for op in ("==", "!=", ">=", "<=", "=>"))

        def is_literalish(n: SliceNode) -> bool:
            label = (n.label or "").upper()
            if label == "LITERAL":
                return True
            code = (normalize_step_code(n.code) if n.code else "").strip()
            if not code:
                return False

            # Numeric literals
            if code.replace(".", "", 1).isdigit():
                return True

            # Boolean/Null literals
            if code.lower() in ("true", "false", "none", "null"):
                return True

            # String literals check: ensure they don't contain interpolation characters
            if ("{" in code or "}" in code or "$" in code) and (
                code.startswith("$") or "{" in code
            ):
                return False

            return (code.startswith('"') and code.endswith('"')) or (
                code.startswith("'") and code.endswith("'")
            )

        def extract_interpolated_vars(code: str) -> list[str]:
            if not code:
                return []
            return re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", code)

        def node_text(
            n: SliceNode,
            *,
            context_file: str | None = None,
            context_method: str | None = None,
            prev_file: str | None = None,
            prev_method: str | None = None,
        ) -> Text:
            txt = Text()
            code = normalize_step_code(n.code) if n.code else ""
            name = n.name or n.label or "?"
            snippet = code or name

            # 1. Location Info
            loc = ""
            file_for_loc = n.parentFile or ""
            if n.lineNumber:
                if prev_file and file_for_loc == prev_file:
                    loc = f"L{n.lineNumber}"
                elif context_file and file_for_loc == context_file:
                    loc = f"L{n.lineNumber}"
                elif file_for_loc:
                    loc = f"{os.path.basename(file_for_loc)}:{n.lineNumber}"
                else:
                    loc = f"L{n.lineNumber}"
            elif file_for_loc and (not context_file or file_for_loc != context_file):
                loc = os.path.basename(file_for_loc)

            if loc:
                txt.append(f"{loc:<14} ", style="location")
            else:
                txt.append(" " * 15)

            # 2. Method Context
            method_full = n.parentMethod or ""
            method_short = short_method(method_full)
            if method_short:
                if prev_method and method_full == prev_method:
                    txt.append(" " * 25)
                elif context_method and method_short == context_method:
                    txt.append(" " * 25)
                else:
                    txt.append(f"{method_short:<24} ", style="method")
            else:
                txt.append(" " * 25)

            # 3. Code Snippet
            txt.append(snippet, style="code")

            # 4. Annotations (Label + Type)
            label_map = {
                "CALL": "Call",
                "LITERAL": "Literal",
                "IDENTIFIER": "Identifier",
                "METHOD_PARAMETER_IN": "Param",
                "METHOD_PARAMETER_OUT": "Param",
                "PARAMETER": "Param",
                "FIELD_IDENTIFIER": "Field",
                "MEMBER": "Member",
                "METHOD_RETURN": "Return",
                "TYPE_REF": "Type",
                "METHOD_REF": "Method",
                "BLOCK": "Block",
                "CONTROL_STRUCTURE": "Control",
            }

            anns = []
            label_text = label_map.get((n.label or "").upper())
            if label_text:
                anns.append(label_text)

            if (
                n.typeFullName
                and n.typeFullName not in {"ANY", "<empty>", ""}
                and "<lambda>" not in n.typeFullName
            ):
                # Get last part of type
                t_name = n.typeFullName.split(".")[-1].split(":")[-1]
                if t_name and t_name not in anns:
                    anns.append(t_name)

            if anns:
                txt.append(f" ({' | '.join(anns)})", style="dim")

            return txt

        def sorted_incoming(node_id: int) -> list[int]:
            edges = rev_adj[node_id]
            return [
                e.src
                for e in sorted(
                    edges,
                    key=lambda e: (
                        nodes[e.src].parentFile or "",
                        nodes[e.src].lineNumber or 0,
                        nodes[e.src].name or "",
                    ),
                )
            ]

        def collect_paths(sink_id: int) -> list[list[int]]:
            paths: list[list[int]] = []
            stack: list[tuple[int, list[int], set[int]]] = [(sink_id, [sink_id], {sink_id})]
            while stack and len(paths) < self.max_paths:
                node_id, path, visited = stack.pop()
                incoming = sorted_incoming(node_id)
                if not incoming or len(path) >= self.max_depth:
                    paths.append(path)
                    continue
                for src_id in incoming:
                    if src_id in visited:
                        continue
                    stack.append((src_id, path + [src_id], visited | {src_id}))
            return paths

        summary = Text.assemble(
            ("Slice summary: ", "bold"),
            (str(len(nodes)), "bold"),
            (" nodes, ", "bold"),
            (str(len(slice_obj.edges)), "bold"),
            (" edges, ", "bold"),
            (str(len(sinks)), "bold"),
            (" sinks", "bold"),
        )
        self.console.print(summary)

        shown_sinks = sinks[: self.max_sinks]
        if len(sinks) > self.max_sinks:
            self.console.print(f"[bold]Showing {self.max_sinks} of {len(sinks)} sinks.[/bold]")

        for i, sink_id in enumerate(shown_sinks, start=1):
            if i > 1:
                self.console.print("")
                self.console.print(Rule(style="dim"))
                self.console.print("")

            sink_node = nodes[sink_id]
            sink_file = sink_node.parentFile or ""
            sink_method = short_method(sink_node.parentMethod)
            header = Text.assemble(
                ("█ ", "red"),
                (f"SINK {i} ", "bold"),
            )
            header.append(node_text(sink_node))
            self.console.print(header)

            paths = collect_paths(sink_id)
            if not paths:
                self.console.print("[yellow]No paths found for sink.[/yellow]")
                continue

            self.console.print(f"[bold]Paths (max {self.max_paths}, depth {self.max_depth})[/bold]")
            unique_paths = []
            seen_paths = set()
            for path in paths:
                compacted = compact_path(list(reversed(path)))
                key = tuple(compacted)
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                unique_paths.append(compacted)

            if len(unique_paths) < len(paths):
                self.console.print(
                    f"[bold]Deduped {len(paths) - len(unique_paths)} similar paths.[/bold]"
                )

            origin_candidates: list[int] = []
            if origin_ids:
                reachable = set()
                queue: list[tuple[int, int]] = [(sink_id, 0)]
                while queue:
                    node_id, depth = queue.pop(0)
                    if node_id in reachable or depth > self.max_depth:
                        continue
                    reachable.add(node_id)
                    for edge in rev_adj.get(node_id, []):
                        queue.append((edge.src, depth + 1))
                origin_candidates = [
                    n_id for n_id in origin_ids if n_id in reachable and n_id != sink_id
                ]
                if not origin_candidates:
                    sink_method = nodes[sink_id].parentMethod or ""
                    origin_candidates = [
                        n_id
                        for n_id in origin_ids
                        if n_id in nodes
                        and n_id != sink_id
                        and (nodes[n_id].parentMethod or "") == sink_method
                    ]
                if origin_candidates:
                    by_name: dict[tuple[str, str], int] = {}
                    for n_id in origin_candidates:
                        node = nodes[n_id]
                        key = (
                            node.parentMethod or "",
                            node.name or normalize_step_code(node.code or ""),
                        )
                        if key not in by_name:
                            by_name[key] = n_id
                            continue
                        if is_parameter_node(node):
                            by_name[key] = n_id
                    origin_candidates = list(by_name.values())
            else:
                origin_seen = set()
                origin_keys = set()
                interp_vars: set[str] = set()
                for n in nodes.values():
                    interp_vars.update(extract_interpolated_vars(n.code or ""))

                explicit_origins: list[int] = []
                if interp_vars:
                    for n_id, n in nodes.items():
                        name = (n.name or "").strip()
                        code = normalize_step_code(n.code) if n.code else ""
                        for var in interp_vars:
                            if (
                                name == var
                                or code == var
                                or code.endswith(f" {var}")
                                or code.startswith(f"{var} ")
                                or f" {var} " in code
                                or code.startswith(f"string {var}")
                            ):
                                explicit_origins.append(n_id)
                                break

                sink_method = nodes[sink_id].parentMethod or ""

                def origin_key(n_id: int) -> tuple[str, str, str]:
                    node = nodes[n_id]
                    code = normalize_step_code(node.code) if node.code else ""
                    name = node.name or ""
                    if is_parameter_node(node):
                        return (node.parentMethod or "", name or code, "param")
                    return (node.parentMethod or "", code or name, "node")

                def add_origin(n_id: int) -> None:
                    if n_id == sink_id:
                        return
                    key = origin_key(n_id)
                    if key in origin_keys:
                        return
                    origin_keys.add(key)
                    if n_id not in origin_seen:
                        origin_seen.add(n_id)
                        origin_candidates.append(n_id)

                for n_id in explicit_origins:
                    add_origin(n_id)

                for compacted in unique_paths:
                    path_origin = None
                    for node_id in compacted:
                        node = nodes[node_id]
                        if node_id in sources or is_parameter_node(node):
                            path_origin = node_id
                            break
                    if path_origin is None:
                        for node_id in compacted:
                            if is_assignment_node(nodes[node_id]):
                                path_origin = node_id
                                break
                    if path_origin is None:
                        for node_id in compacted:
                            if not is_literalish(nodes[node_id]):
                                path_origin = node_id
                                break
                    if path_origin is None and compacted:
                        path_origin = compacted[0]
                    if path_origin is not None:
                        add_origin(path_origin)

                if origin_candidates:
                    # Sequential filtering for higher-quality origins

                    # 1. Remove literals (unless nothing else exists)
                    non_literal = [
                        n_id for n_id in origin_candidates if not is_literalish(nodes[n_id])
                    ]
                    if non_literal:
                        origin_candidates = non_literal

                    # 2. Remove likely constants (UPPER_CASE)
                    non_constant = [
                        n_id
                        for n_id in origin_candidates
                        if not (
                            nodes[n_id].name
                            and nodes[n_id].name.isupper()
                            and len(nodes[n_id].name) > 2
                        )
                    ]
                    if non_constant:
                        origin_candidates = non_constant

                    # 3. Prioritize actual parameters
                    params = [n_id for n_id in origin_candidates if is_parameter_node(nodes[n_id])]
                    if params:
                        origin_candidates = params

                    # 4. Final filter: same method as sink is usually better for evidence
                    same_method = [
                        n_id
                        for n_id in origin_candidates
                        if (nodes[n_id].parentMethod or "") == sink_method
                    ]
                    if same_method:
                        origin_candidates = same_method

            if origin_candidates:
                self.console.print("[bold]Origin candidates[/bold]")
                for origin_id in origin_candidates:
                    origin_node = nodes[origin_id]
                    line = node_text(
                        origin_node,
                        context_file=sink_file,
                        context_method=sink_method,
                    )
                    line.stylize("bold green")
                    self.console.print(Text("  - ", style="bold") + line)

            if self.show_evidence and origin_candidates:
                origin_set = set(origin_candidates)
                queue: list[int] = [sink_id]
                parents: dict[int, int | None] = {sink_id: None}
                found_origin = None
                depth_map: dict[int, int] = {sink_id: 0}
                while queue:
                    node_id = queue.pop(0)
                    if node_id in origin_set:
                        found_origin = node_id
                        break
                    if depth_map.get(node_id, 0) >= self.max_depth:
                        continue
                    for edge in rev_adj.get(node_id, []):
                        if edge.src in parents:
                            continue
                        parents[edge.src] = node_id
                        depth_map[edge.src] = depth_map.get(node_id, 0) + 1
                        queue.append(edge.src)

                if found_origin is not None:
                    self.console.print("[bold]Evidence chain[/bold]")
                    chain_sink_to_source = []
                    curr = found_origin
                    while curr is not None:
                        chain_sink_to_source.append(curr)
                        curr = parents.get(curr)

                    compacted_chain = compact_path(chain_sink_to_source)

                    prev_f, prev_m = None, None
                    for step_i, node_id in enumerate(compacted_chain, start=1):
                        node = nodes[node_id]
                        prefix = Text(f"  {step_i:>2}. ", style="bold")
                        line = node_text(
                            node,
                            context_file=sink_file,
                            context_method=sink_method,
                            prev_file=prev_f,
                            prev_method=prev_m,
                        )
                        prev_f, prev_m = node.parentFile, node.parentMethod
                        if node_id == found_origin:
                            line.stylize("bold green")
                        if node_id == sink_id:
                            line.stylize("bold red")
                        self.console.print(prefix + line)
                else:
                    self.console.print("[bold]Evidence chain[/bold]")
                    self.console.print("[bold]  - No path from origin to sink within depth[/bold]")

            if self.show_paths:
                for p_i, compacted in enumerate(unique_paths, start=1):
                    self.console.print(f"[bold]Path {p_i}[/bold]")
                    prev_f, prev_m = None, None
                    for step_i, node_id in enumerate(compacted, start=1):
                        node = nodes[node_id]
                        prefix = Text(f"  {step_i:>2}. ", style="bold")
                        line = node_text(
                            node,
                            context_file=sink_file,
                            context_method=sink_method,
                            prev_file=prev_f,
                            prev_method=prev_m,
                        )
                        prev_f, prev_m = node.parentFile, node.parentMethod
                        if node_id in sources:
                            line.stylize("bold green")
                        if is_parameter_node(node) and node_id not in sources:
                            line.stylize("bold green")
                        if node_id == sink_id:
                            line.stylize("bold red")
                        self.console.print(prefix + line)


class UsageSliceReporter(Reporter):
    def __init__(self, console: Console | None = None):
        self.console = console or Console(theme=custom_theme)

    def report(self, usage_slice: dict[str, Any]):
        if not usage_slice or "objectSlices" not in usage_slice:
            self.console.print("[yellow]No usage slices found.[/yellow]")
            return

        for i, obj_slice in enumerate(usage_slice["objectSlices"]):
            full_name = obj_slice.get("fullName", "Unknown")
            file_name = obj_slice.get("fileName", "?")
            line = obj_slice.get("lineNumber", "?")

            header = Text.assemble(
                ("█ ", "blue"),
                ("USAGES ", "bold"),
                (f"{full_name} ", "bold cyan"),
                (f"({file_name}:{line})", "location"),
            )

            if i > 0:
                self.console.print("")
                self.console.print(Rule(style="dim"))
                self.console.print("")

            self.console.print(header)

            for sl in obj_slice.get("slices", []):
                try:
                    target = json.loads(sl["targetObj"])
                    defined_by = json.loads(sl["definedBy"])
                except Exception:
                    continue

                target_name = target.get("name", "obj")
                target_type = target.get("typeFullName", "ANY")

                tree = Tree(
                    Text.assemble(
                        ("Object ", "dim"),
                        (target_name, "bold green"),
                        (f": {target_type}", "dim"),
                    )
                )

                def_text = Text.assemble(
                    ("Defined by: ", "dim"),
                    (defined_by.get("name", "unknown"), "bold magenta"),
                    (f" (line {defined_by.get('lineNumber', '?')})", "location"),
                )
                tree.add(def_text)

                calls = tree.add("Calls")

                def _get_line(c):
                    ln = c.get("lineNumber", "?")
                    if isinstance(ln, list):
                        return str(ln[0]) if ln else "?"
                    return str(ln)

                invoked = sl.get("invokedCalls", [])
                for call in invoked:
                    calls.add(
                        Text.assemble(
                            ("Invoked: ", "dim"),
                            (call.get("callName", "call"), "bold yellow"),
                            (f" (line {_get_line(call)})", "location"),
                        )
                    )

                arg_to = sl.get("argToCalls", [])
                for call in arg_to:
                    pos = call.get("position", "?")
                    calls.add(
                        Text.assemble(
                            ("Passed as arg ", "dim"),
                            (str(pos), "bold"),
                            (" to: ", "dim"),
                            (call.get("callName", "call"), "bold yellow"),
                            (f" (line {_get_line(call)})", "location"),
                        )
                    )

                self.console.print(tree)


class SarifReporter(Reporter):
    def __init__(self, output_path: str, base_path: str = ""):
        self.output_path = output_path
        self.base_path = base_path
        self.results: list[om.Result] = []
        self.rules: dict[str, om.ReportingDescriptor] = {}

    def report(self, rule: ScanRule, matches: list[Match]):
        rule_id = rule.rule_id
        assert rule_id is not None
        # Add rule to tool rules if not already present
        if rule_id not in self.rules:
            self.rules[rule_id] = om.ReportingDescriptor(
                id=rule_id,
                name=rule.name,
                shortDescription=om.MultiformatMessageString(text=rule.description or rule.name),
                fullDescription=om.MultiformatMessageString(
                    text=(
                        f"Root Cause: {rule.root_cause}\nImpact: {rule.impact}"
                        if rule.root_cause and rule.impact
                        else (rule.description or rule.name)
                    )
                ),
                help=om.MultiformatMessageString(
                    text=f"Root Cause: {rule.root_cause}\nImpact: {rule.impact}"
                ),
            )

        for match in matches:
            abs_path = resolve_file_path(self.base_path, match.file)
            start_line, start_col, end_line, end_col = resolve_region(
                abs_path,
                match.line,
                match.column,
                match.code,
            )

            region = om.Region1(
                startLine=start_line,
                startColumn=start_col,
            )
            if end_line:
                region["endLine"] = end_line
            if end_col:
                region["endColumn"] = end_col

            result = om.Result(
                ruleId=rule_id,
                message=om.Message1(text=f"Potential {rule.name} found."),
                level=(
                    "error"
                    if rule.severity >= Severity.high
                    else "warning"
                    if rule.severity == Severity.medium
                    else "note"
                ),
                rank={
                    "high": 100.0,
                    "medium": 70.0,
                    "low": 30.0,
                }.get(rule.confidence_name, 50.0),
                locations=[
                    om.Location(
                        physicalLocation=om.PhysicalLocation2(
                            artifactLocation=om.ArtifactLocation(
                                uri=match.file,
                            ),
                            region=region,
                        )
                    )
                ],
            )

            if match.flow:
                thread_flow_locations: list[om.ThreadFlowLocation] = []
                for step_model in match.flow:
                    step_abs_path = resolve_file_path(self.base_path, step_model.file)
                    s_start_line, s_start_col, s_end_line, s_end_col = resolve_region(
                        step_abs_path,
                        step_model.line,
                        step_model.column,
                        step_model.code,
                    )

                    step_region = om.Region1(
                        startLine=s_start_line,
                        startColumn=s_start_col,
                    )
                    if s_end_line:
                        step_region["endLine"] = s_end_line
                    if s_end_col:
                        step_region["endColumn"] = s_end_col

                    thread_flow_locations.append(
                        om.ThreadFlowLocation(
                            location=om.Location(
                                physicalLocation=om.PhysicalLocation2(
                                    artifactLocation=om.ArtifactLocation(uri=step_model.file),
                                    region=step_region,
                                ),
                                message=om.Message1(text=step_model.code),
                            )
                        )
                    )
                result["codeFlows"] = [
                    om.CodeFlow(threadFlows=[om.ThreadFlow(locations=thread_flow_locations)])
                ]
            self.results.append(result)

    def finalize(self):
        log: om.StaticAnalysisResultsFormatSarifVersion210JsonSchema = {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Hoppy",
                            "version": "1.0.0",
                            "rules": list(self.rules.values()),
                        }
                    },
                    "results": self.results,
                }
            ],
        }
        with open(self.output_path, "w") as f:
            json.dump(log, f, indent=2)
