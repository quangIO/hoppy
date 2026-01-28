import os
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Represents values bound to metavariables, usually strings (code)
# but could be numbers or other JSON-serializable types from Joern.
BindingValue = str | int | float | bool | None


def coerce_int(v: Any) -> int | None:
    """Helper to convert various Joern outputs to optional integers."""
    match v:
        case None | "":
            return None
        case int():
            return v
        case str():
            try:
                return int(v)
            except ValueError:
                return None
        case _:
            return None


class JoernNode(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str = ""
    code: str = ""
    lineNumber: int | None = None
    columnNumber: int | None = None
    lineNumberEnd: int | None = None
    columnNumberEnd: int | None = None
    filename: str = ""
    methodFullName: str = ""
    typeDeclFullName: str = ""

    @field_validator(
        "lineNumber", "columnNumber", "lineNumberEnd", "columnNumberEnd", mode="before"
    )
    @classmethod
    def _validate_ints(cls, v: Any) -> int | None:
        return coerce_int(v)


class JoernLocation(BaseModel):
    model_config = ConfigDict(extra="allow")
    filename: str = ""
    line: int | None = None
    column: int | None = None

    @field_validator("line", "column", mode="before")
    @classmethod
    def _validate_ints(cls, v: Any) -> int | None:
        return coerce_int(v)


class FlowStepModel(BaseModel):
    file: str = ""
    line: int | None = None
    column: int | None = None
    method: str = ""
    code: str = ""
    lineNumberEnd: int | None = None
    columnNumberEnd: int | None = None

    @field_validator("line", "column", "lineNumberEnd", "columnNumberEnd", mode="before")
    @classmethod
    def _validate_ints(cls, v: Any) -> int | None:
        return coerce_int(v)

    @model_validator(mode="before")
    @classmethod
    def from_any(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return {
                "file": data.get("filename") or data.get("file") or data.get("parentFile") or "",
                "line": data.get("lineNumber") or data.get("line"),
                "column": data.get("columnNumber") or data.get("column"),
                "method": data.get("methodFullName")
                or data.get("method")
                or data.get("parentMethod")
                or "",
                "code": str(data.get("code", "")),
                "lineNumberEnd": data.get("lineNumberEnd"),
                "columnNumberEnd": data.get("columnNumberEnd"),
            }
        return {"code": str(data)}

    def format(self) -> str:
        c_clean = self.code.replace("\n", " ").strip()
        f = self.file
        line = self.line if self.line is not None else ""
        col = self.column if self.column is not None else ""
        m = self.method
        le = self.lineNumberEnd if self.lineNumberEnd is not None else ""
        ce = self.columnNumberEnd if self.columnNumberEnd is not None else ""

        return f"{f}:{line}:{col}:{m}:{c_clean}:{le}:{ce}"


class Match(BaseModel):
    model_config = ConfigDict(frozen=True)

    data: dict[str, Any]
    containing_method: str = ""
    bindings: dict[str, BindingValue] = Field(default_factory=dict)
    flow: list[FlowStepModel] = Field(default_factory=list)
    node_loc: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def node_data(self) -> JoernNode:
        return JoernNode.model_validate(self.data)

    @property
    def loc_data(self) -> JoernLocation | None:
        if not self.node_loc:
            return None
        try:
            return JoernLocation.model_validate(self.node_loc)
        except Exception:
            return None

    @property
    def code(self) -> str:
        return self.node_data.code

    @property
    def line(self) -> int | None:
        val = self.node_data.lineNumber or (self.loc_data.line if self.loc_data else None)
        return val

    @property
    def column(self) -> int | None:
        val = self.node_data.columnNumber or (self.loc_data.column if self.loc_data else None)
        return val

    @property
    def end_line(self) -> int | None:
        val = self.node_data.lineNumberEnd or (
            coerce_int(self.node_loc.get("lineNumberEnd")) if self.node_loc else None
        )
        return val

    @property
    def end_column(self) -> int | None:
        val = self.node_data.columnNumberEnd or (
            coerce_int(self.node_loc.get("columnNumberEnd")) if self.node_loc else None
        )
        return val

    @property
    def called_method(self) -> str:
        return self.node_data.methodFullName

    @property
    def class_name(self) -> str:
        """Returns the full name of the class (TypeDecl) containing this match."""
        full = self.node_data.typeDeclFullName
        if not full or full in ("<empty>", "<unknown>", "ANY"):
            # Fallback: extract from method_fullname
            # Handle C#: Namespace.Class.Method:Signature
            # Handle Java: com.package.Class.method:signature
            candidate = self.method_fullname
            if ":" in candidate:
                segments = [seg for seg in candidate.split(":") if seg]
                if segments:
                    last = segments[-1]
                    if any(
                        segments[0].endswith(ext)
                        for ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
                    ):
                        candidate = last
                    elif len(segments) >= 2:
                        candidate = segments[-2]

            # Now we have something like com.package.Class.method
            # Strip method if it's there
            parts = candidate.split("(")[0].split(".")
            if len(parts) >= 2:
                # If the last part is the method name, the class name is everything before it
                if parts[-1] == self.method_name:
                    return ".".join(parts[:-1])
                return ".".join(parts)
            return parts[-1] if parts else "<unknown>"

        # Special handling for JS/TS generic program wrappers
        if full.endswith("::program"):
            base = full.replace("::program", "")
            if "/" in base or "\\" in base:
                base = base.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            return os.path.splitext(base)[0]
        if full == "program":
            # Try to get it from filename
            if self.file:
                base = self.file
                if "/" in base or "\\" in base:
                    base = base.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                return os.path.splitext(base)[0]
            return "program"

        # If the type name seems to include the method name (common in some
        # Joern frontends fallbacks)
        # we try to strip it if it's redundant with method_name
        parts = full.split(".")
        if len(parts) >= 2 and parts[-1] == self.method_name:
            return ".".join(parts[:-1])
        return full

    @property
    def method_fullname(self) -> str:
        return self.containing_method or self.called_method

    @property
    def method_name(self) -> str:
        """Returns the simple name of the method (e.g., 'Import' instead of the full signature)."""
        # If the node itself is a method/call and has a simple name, use it
        if self.node_data.name and self.node_data.name != "<unknown>":
            if not self.node_data.name.startswith("<operator>"):
                return self.node_data.name

        # Fallback: Robustly parse method_fullname
        return self.method_fullname.split("(")[0].split(":")[0].split(".")[-1]

    @property
    def file(self) -> str:
        f = self.node_data.filename or (self.loc_data.filename if self.loc_data else "")
        if not f or f == "N/A":
            # Joern often omits filename for single-file imports in Python.
            # It's usually present in the methodFullName like "file.py:<module>.method"
            if ":" in self.method_fullname:
                parts = self.method_fullname.split(":")
                if parts[0] and ("." in parts[0] or "/" in parts[0] or "\\" in parts[0]):
                    f = parts[0]

            # Fallback to metadata if available
            if (not f or f == "N/A") and self.metadata:
                root = self.metadata.get("root", "")
                if root:
                    # Root might be a path like "/path/to/file.py/"
                    f_val = root.rstrip("/")
                    if os.path.isfile(f_val):
                        f = os.path.basename(f_val)
                    elif os.path.isdir(f_val):
                        # If it's a dir, we still don't know the file, but it's better than nothing
                        f = os.path.basename(f_val)
                    else:
                        # Could be a partial path or already just a filename
                        f = os.path.basename(f_val)

            # Fallback to flow steps if available
            if (not f or f == "N/A") and self.flow:
                for step in reversed(self.flow):
                    if step.file and step.file != "N/A":
                        f = step.file
                        break
        return f

    def __repr__(self):
        bind_str = f" | bindings={self.bindings}" if self.bindings else ""
        flow_str = f" | flow_len={len(self.flow)}" if self.flow else ""
        line_str = str(self.line) if self.line is not None else "?"
        return f"<Match {self.file}:{line_str} | {self.code[:50]}{bind_str}{flow_str}>"

    @classmethod
    def from_json(
        cls,
        data: dict[str, Any],
        mvar_names: list[str] | None = None,
    ) -> "Match":
        # Only support modern format (Named Keys from ujson.Obj)
        if "node" not in data:
            # Standalone node (not a tuple) - fallback for simple queries
            return cls(data=data)

        core_data = data["node"]
        containing_method = data.get("method", "")
        type_decl_full_name = data.get("className", "")
        bindings = data.get("bindings", {})
        flow_data = data.get("trace", [])
        node_loc = data.get("loc", {})
        metadata = data.get("metadata", {})

        # Inject into core_data so JoernNode validator picks it up
        if isinstance(core_data, dict):
            core_data["typeDeclFullName"] = type_decl_full_name
            if containing_method and not core_data.get("methodFullName"):
                core_data["methodFullName"] = containing_method

        flow = [FlowStepModel.model_validate(step) for step in flow_data]

        return cls(
            data=core_data,
            containing_method=containing_method,
            bindings=bindings,
            flow=flow,
            node_loc=node_loc,
            metadata=metadata,
        )
