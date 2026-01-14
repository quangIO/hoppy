from dataclasses import dataclass, field, replace

from .patterns import Pattern, Var


@dataclass(frozen=True)
class Query:
    _source: Pattern | None = None
    _source_arg_index: int | None = None
    _force_source_parameter: bool = False
    _include_trace: bool = True
    _steps: list[Pattern] = field(default_factory=list)
    _sanitizers: list[Pattern] = field(default_factory=list)
    _filters: list[str] = field(default_factory=list)
    _mvar_names: list[str] = field(default_factory=list)

    @classmethod
    def source(cls, pattern: Pattern, arg_index: int | None = None) -> "Query":
        force_source_parameter = False
        # Special case: if source is a Var, we want it to be a parameter (untrusted input)
        # to avoid starting flows from internal constants or intermediate variables.
        match pattern:
            case Var():
                force_source_parameter = True

        # Extract unique metavariable names
        mvars = pattern._get_metavariables(arg_index=arg_index)
        mvar_names = []
        seen = set()
        for mv in mvars:
            if mv["name"] not in seen:
                mvar_names.append(mv["name"])
                seen.add(mv["name"])

        return cls(
            _source=pattern,
            _source_arg_index=arg_index,
            _force_source_parameter=force_source_parameter,
            _mvar_names=mvar_names,
        )

    def flows_to(self, pattern: Pattern) -> "Query":
        """Adds a taint flow step. If called multiple times, creates a chain."""
        new_steps = self._steps + [pattern]
        # Add new metavariables from this pattern too
        mvars = pattern._get_metavariables()
        new_mvar_names = list(self._mvar_names)
        seen = set(new_mvar_names)
        for mv in mvars:
            if mv["name"] not in seen:
                new_mvar_names.append(mv["name"])
                seen.add(mv["name"])
        return replace(self, _steps=new_steps, _mvar_names=new_mvar_names)

    def __rshift__(self, other: Pattern) -> "Query":
        """Syntax Sugar for flows_to."""
        return self.flows_to(other)

    def passes_not(self, pattern: Pattern) -> "Query":
        new_sanitizers = self._sanitizers + [pattern]
        return replace(self, _sanitizers=new_sanitizers)

    def with_trace(self, include: bool = True) -> "Query":
        """Toggle inclusion of flow trace data for performance-sensitive scans."""
        return replace(self, _include_trace=include)

    def summary(self) -> "Query":
        """Disable flow trace generation to reduce output size."""
        return self.with_trace(False)

    def generate_scala(self) -> str:
        from ..compiler.scala import compile_query

        return compile_query(self)
