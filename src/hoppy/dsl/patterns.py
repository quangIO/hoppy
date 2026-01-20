from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TypedDict


class MetavariableInfo(TypedDict):
    name: str
    type: str
    index: int | None


# Types that can be represented as literals in Joern CPGs
LiteralValue = str | int | float | bool | None


def _esc(s: str | None) -> str:
    """Escapes a string for use in a Scala string literal."""
    if s is None:
        return ""
    return json.dumps(s)[1:-1]


@dataclass
class Pattern(ABC):
    """Base class for all patterns."""

    @abstractmethod
    def to_cpg(self) -> str:
        """Returns the base CPG query (e.g. cpg.call)."""
        pass

    @abstractmethod
    def to_cpg_traversal(self) -> str:
        """Returns the traversal step to check this pattern against a node."""
        pass

    def to_cpg_predicate(self) -> str:
        """Returns a Scala predicate (as a string) to check if a node matches this pattern."""
        return f"((node: nodes.StoredNode) => {self.to_scala_predicate('node')})"

    def to_scala_predicate(self, node_var: str) -> str:
        """Returns the Scala logic for the predicate as a boolean expression."""
        # Default implementation uses to_cpg_traversal on a temporary traversal
        return f"({node_var}.start{self.to_cpg_traversal()}.nonEmpty)"

    def where(self, other: Pattern) -> Pattern:
        """Combines this pattern with another using AND logic."""
        return And([self, other])

    def inside(self, context: Pattern) -> Pattern:
        """Filters this pattern to be inside a context (e.g. a Method)."""
        return self.where(Inside(context))

    def is_dominated_by(self, dominator: Pattern) -> Pattern:
        """Matches if this node is dominated by another in the CFG."""
        return self.where(DominatedBy(dominator))

    def is_not_dominated_by(self, dominator: Pattern) -> Pattern:
        """Matches if this node is NOT dominated by another (e.g. missing check)."""
        return self.where(Not(DominatedBy(dominator)))

    def field(self, name: str) -> Pattern:
        """Matches a field access on this pattern (e.g. user.id)."""
        return Field(receiver=self, name=name)

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        """Internal helper to find metavariables in the pattern tree."""
        return []

    def __or__(self, other: Pattern) -> Pattern:
        """Syntax for Or: PatternA | PatternB"""
        return Or([self, other])

    def __and__(self, other: Pattern) -> Pattern:
        """Syntax for And: PatternA & PatternB"""
        return And([self, other])

    def __invert__(self) -> Pattern:
        """Syntax for Not: ~PatternA"""
        return Not(self)


@dataclass
class Parameter(Pattern):
    """Matches a method parameter, optionally filtering by name or annotation."""

    name: str | None = None
    annotation: str | None = None

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        match self.name:
            case str(n) if n.startswith("$"):
                return [{"name": n, "type": "parameter", "index": arg_index}]
            case _:
                return []

    def to_cpg(self) -> str:
        q = "cpg.parameter"
        match self.name:
            case str(n) if not n.startswith("$"):
                q += f'.name("{_esc(n)}")'
        if self.annotation:
            q += f'.annotation.name("{_esc(self.annotation)}")'
        return q

    def to_cpg_traversal(self) -> str:
        q = ".collectAll[nodes.MethodParameterIn]"
        match self.name:
            case str(n) if not n.startswith("$"):
                q += f'.name("{_esc(n)}")'
        if self.annotation:
            q += f'.annotation.name("{_esc(self.annotation)}")'
        return q

    def to_scala_predicate(self, node_var: str) -> str:
        # Check if it's a Parameter node and matches filters
        q = "case p: nodes.MethodParameterIn => "
        filters = []
        match self.name:
            case str(n) if not n.startswith("$"):
                filters.append(f'p.name.matches("{_esc(n)}")')
        if self.annotation:
            filters.append(
                f'p.start.annotation.name.filter(_.matches("{_esc(self.annotation)}")).nonEmpty'
            )

        if not filters:
            q += "true"
        else:
            q += " && ".join(filters)
        q += " ; case _ => false"
        return f"({node_var} match {{ {q} }})"


@dataclass
class Var(Pattern):
    """Matches any expression and binds it to a metavariable name (e.g. $X)."""

    name: str

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        return [{"name": self.name, "type": "var", "index": arg_index}]

    def to_cpg(self) -> str:
        # Matches expressions or method parameters
        return "(cpg.expression ++ cpg.parameter)"

    def to_cpg_traversal(self) -> str:
        # Match anything
        return ""

    def to_scala_predicate(self, node_var: str) -> str:
        return "true"


@dataclass
class Literal(Pattern):
    """Matches a literal value."""

    value: LiteralValue

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        match self.value:
            case str(v) if v.startswith("$"):
                return [{"name": v, "type": "literal", "index": arg_index}]
            case _:
                return []

    def _escape_scala(self, s: LiteralValue) -> str:
        if isinstance(s, str):
            # Joern stores string literals with quotes in their .code property
            # We need to generate Scala code that represents the string "s"
            # This works for both process and server modes
            return json.dumps(json.dumps(s))
        # For non-strings (like numbers), we still need to pass a string to .code()
        return json.dumps(str(s))

    def _string_checks(self, node_var: str) -> str:
        escaped = _esc(str(self.value))
        return f'{node_var}.code == "\\"{escaped}\\"" || {node_var}.code == "{escaped}"'

    def to_cpg(self) -> str:
        match self.value:
            case str(v) if v.startswith("$"):
                return "cpg.literal"
            case str(_):
                return f"cpg.literal.filter(l => {self._string_checks('l')})"
            case _:
                return f"cpg.literal.code({self._escape_scala(self.value)})"

    def to_cpg_traversal(self) -> str:
        match self.value:
            case str(v) if v.startswith("$"):
                return ".collectAll[nodes.Literal]"
            case str(_):
                return f".collectAll[nodes.Literal].filter(l => {self._string_checks('l')})"
            case _:
                return f".collectAll[nodes.Literal].code({self._escape_scala(self.value)})"

    def to_scala_predicate(self, node_var: str) -> str:
        q = "case l: nodes.Literal => "
        match self.value:
            case str(v) if v.startswith("$"):
                q += "true"
            case str(_):
                q += self._string_checks("l")
            case _:
                q += f"l.code == {self._escape_scala(self.value)}"
        q += " ; case _ => false"
        return f"({node_var} match {{ {q} }})"


@dataclass
class Identifier(Pattern):
    """Matches a variable/identifier name."""

    name: str

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        match self.name:
            case str(n) if n.startswith("$"):
                return [{"name": n, "type": "identifier", "index": arg_index}]
            case _:
                return []

    def to_cpg(self) -> str:
        match self.name:
            case str(n) if n.startswith("$"):
                return "cpg.identifier"
            case str(n):
                return f'cpg.identifier.name("{_esc(n)}")'

    def to_cpg_traversal(self) -> str:
        match self.name:
            case str(n) if n.startswith("$"):
                return ".collectAll[nodes.Identifier]"
            case str(n):
                # We use collectAll because the previous node might be an Expression
                # and we want to ensure we only filter Identifier nodes that have a 'name'
                return f'.collectAll[nodes.Identifier].name("{_esc(n)}")'

    def to_scala_predicate(self, node_var: str) -> str:
        q = "case i: nodes.Identifier => "
        match self.name:
            case str(n) if n.startswith("$"):
                q += "true"
            case str(n):
                q += f'i.name.matches("{_esc(n)}")'
        q += " ; case _ => false"
        return f"({node_var} match {{ {q} }})"


@dataclass
class Call(Pattern):
    """Matches a function call."""

    name: str | None = None
    fullname: str | None = None
    receiver_type: str | None = None
    args: list[Pattern | LiteralValue] = field(default_factory=list)

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        mvars: list[MetavariableInfo] = []
        match self.name:
            case str(n) if n.startswith("$"):
                mvars.append({"name": n, "type": "call_name", "index": None})

        for i, arg in enumerate(self.args):
            match arg:
                case str(s) if s.startswith("$"):
                    arg_p = Var(s)
                case Pattern() as p:
                    arg_p = p
                case _:
                    arg_p = Literal(arg)
            mvars.extend(arg_p._get_metavariables(arg_index=i + 1))
        return mvars

    def to_cpg(self) -> str:
        q = "cpg.call"
        if self.fullname:
            q += f'.methodFullName("{_esc(self.fullname)}")'
        else:
            match self.name:
                case str(n) if not n.startswith("$"):
                    q += f'.name("{_esc(self.name)}")'

        # Add filters for receiver, arguments, and unification
        return q + self._get_filters_traversal()

    def to_cpg_traversal(self) -> str:
        q = ".collectAll[nodes.Call]"
        if self.fullname:
            q += f'.methodFullName("{_esc(self.fullname)}")'
        else:
            match self.name:
                case str(n) if not n.startswith("$"):
                    q += f'.name("{_esc(self.name)}")'

        return q + self._get_filters_traversal()

    def to_scala_predicate(self, node_var: str) -> str:
        q = "case c: nodes.Call => "
        filters = []
        if self.fullname:
            filters.append(f'c.methodFullName.matches("{_esc(self.fullname)}")')
        else:
            match self.name:
                case str(n) if not n.startswith("$"):
                    filters.append(f'c.name == "{_esc(n)}"')

        # Add filters for arguments if any
        for i, arg in enumerate(self.args):
            match arg:
                case str(s) if s.startswith("$"):
                    arg_p = Var(s)
                case Pattern() as p:
                    arg_p = p
                case _:
                    arg_p = Literal(arg)

            arg_pred = arg_p.to_cpg_predicate()
            filters.append(f"c.argument.size >= {i + 1} && {arg_pred}(c.argument({i + 1}))")

        if not filters:
            q += "true"
        else:
            q += " && ".join(filters)
        q += " ; case _ => false"
        return f"({node_var} match {{ {q} }})"

    def _get_filters_traversal(self) -> str:
        q = ""
        if self.receiver_type:
            type_regex = f".*{_esc(self.receiver_type)}.*"
            # Use property[String] to avoid Iterator[Nothing] issues
            q += (
                f'.where(_.argument(0).property[String]("TYPE_FULL_NAME")'
                f'.filter(_.matches("{type_regex}")))'
            )

        for i, arg in enumerate(self.args):
            match arg:
                case str(s) if s.startswith("$"):
                    arg_p = Var(s)
                case Pattern() as p:
                    arg_p = p
                case _:
                    arg_p = Literal(arg)

            traversal = arg_p.to_cpg_traversal()
            # Even if traversal is empty (like Var matching anything),
            # we want to ensure the argument exists.
            q += f".where(_.argument({i + 1}){traversal})"

        # Handle Metavariable Equality within the call
        mvars = self._get_metavariables()
        by_name = {}
        for mv in mvars:
            by_name.setdefault(mv["name"], []).append(mv)

        for name, occurrences in by_name.items():
            if len(occurrences) > 1:
                first = occurrences[0]
                for other in occurrences[1:]:
                    match (first.get("index"), other.get("index")):
                        case (int(idx1), int(idx2)):
                            max_idx = max(idx1, idx2)
                            q += (
                                f".filter(c => try {{ c.argument.size >= {max_idx} && "
                                f"c.argument({idx1}).code == c.argument({idx2}).code }} "
                                f"catch {{ case _: Exception => false }})"
                            )
        return q


@dataclass
class DominatedBy(Pattern):
    """Matches if the current node is dominated by another pattern in the CFG."""

    dominator: Pattern

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        return self.dominator._get_metavariables(arg_index)

    def to_cpg(self) -> str:
        return f"cpg.all{self.to_cpg_traversal()}"

    def to_cpg_traversal(self) -> str:
        # node.dominatedBy(pattern)
        # Note: dominatedBy expects a traversal
        return f".collectAll[nodes.CfgNode].where(_.dominatedBy{self.dominator.to_cpg_traversal()})"


@dataclass
class Method(Pattern):
    """Matches a method/function definition."""

    name: str | None = None
    fullname: str | None = None
    annotation: str | None = None

    def to_cpg(self) -> str:
        q = "cpg.method"
        if self.fullname:
            q += f'.fullName("{_esc(self.fullname)}")'
        elif self.name:
            q += f'.name("{_esc(self.name)}")'

        if self.annotation:
            q += f'.where(_.annotation.name("{_esc(self.annotation)}"))'
        return q

    def to_cpg_traversal(self) -> str:
        q = ".collectAll[nodes.Method]"
        if self.fullname:
            q += f'.fullName("{_esc(self.fullname)}")'
        elif self.name:
            q += f'.name("{_esc(self.name)}")'

        if self.annotation:
            q += f'.where(_.annotation.name("{_esc(self.annotation)}"))'
        return q

    def to_scala_predicate(self, node_var: str) -> str:
        q = "case m: nodes.Method => "
        filters = []
        if self.fullname:
            filters.append(f'm.fullName.matches(".*({_esc(self.fullname)}).*")')
        elif self.name:
            filters.append(f'm.name.matches(".*({_esc(self.name)}).*")')

        if self.annotation:
            # Check annotation on the method OR on the enclosing class (TypeDecl)
            filters.append(
                f"("
                f'm.start.annotation.name.filter(_.matches("{_esc(self.annotation)}")).nonEmpty || '
                f'm.start.typeDecl.annotation.name.filter(_.matches("{_esc(self.annotation)}")).nonEmpty'
                f")"
            )

        if not filters:
            q += "true"
        else:
            q += " && ".join(filters)
        q += " ; case _ => false"
        return f"({node_var} match {{ {q} }})"


@dataclass
class Inside(Pattern):
    """Matches if the current node is inside a specific context (like a Method)."""

    context: Pattern

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        return self.context._get_metavariables(arg_index)

    def to_cpg(self) -> str:
        return f"cpg.all{self.to_cpg_traversal()}"

    def to_cpg_traversal(self) -> str:
        # Generic recursive implementation:
        # Check if the enclosing method node matches the context pattern.
        return f".where(_.method.filter(node => {self.context.to_scala_predicate('node')}))"


@dataclass
class Or(Pattern):
    """Matches any of the provided patterns."""

    patterns: list[Pattern]

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        mvars: list[MetavariableInfo] = []
        seen_names = set()
        for p in self.patterns:
            for mv in p._get_metavariables(arg_index):
                if mv["name"] not in seen_names:
                    mvars.append(mv)
                    seen_names.add(mv["name"])
        return mvars

    def to_cpg(self) -> str:
        # Union of traversals
        # (traversal1 ++ traversal2).distinct
        parts = [p.to_cpg() for p in self.patterns]
        if not parts:
            return "cpg.all"
        return f"({' ++ '.join(parts)}).distinct"

    def to_cpg_traversal(self) -> str:
        # Match if any sub-pattern matches
        combined = " || ".join([p.to_scala_predicate("node") for p in self.patterns])
        return f".filter(node => {combined})"

    def to_scala_predicate(self, node_var: str) -> str:
        preds = [p.to_scala_predicate(node_var) for p in self.patterns]
        combined = " || ".join(preds)
        return f"({combined})"


@dataclass
class And(Pattern):
    """Matches only if all provided patterns match."""

    patterns: list[Pattern]

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        mvars: list[MetavariableInfo] = []
        for p in self.patterns:
            mvars.extend(p._get_metavariables(arg_index))
        return mvars

    def to_cpg(self) -> str:
        # Intersection of traversals is hard in Joern.
        # Usually we start with one and filter by others.
        if not self.patterns:
            return "cpg.all"

        first = self.patterns[0]
        others = self.patterns[1:]
        base = first.to_cpg()
        filters = [p.to_cpg_traversal() for p in others]
        return base + "".join(filters)

    def to_cpg_traversal(self) -> str:
        return "".join([p.to_cpg_traversal() for p in self.patterns])

    def to_scala_predicate(self, node_var: str) -> str:
        preds = [p.to_scala_predicate(node_var) for p in self.patterns]
        combined = " && ".join(preds)
        return f"({combined})"


@dataclass
class Not(Pattern):
    """Matches only if the provided pattern does NOT match."""

    pattern: Pattern

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        return self.pattern._get_metavariables(arg_index)

    def to_cpg(self) -> str:
        # This is very broad: cpg.all.filterNot(...)
        return f"cpg.all{self.to_cpg_traversal()}"

    def to_cpg_traversal(self) -> str:
        return f".filterNot(node => {self.pattern.to_scala_predicate('node')})"

    def to_scala_predicate(self, node_var: str) -> str:
        return f"!({self.pattern.to_scala_predicate(node_var)})"


@dataclass
class Field(Pattern):
    """Matches a field access (e.g. obj.field)."""

    receiver: Pattern
    name: str

    def _get_metavariables(self, arg_index: int | None = None) -> list[MetavariableInfo]:
        return self.receiver._get_metavariables(arg_index)

    def to_cpg(self) -> str:
        # Field access in Joern is a call to <operator>.fieldAccess or similar
        return 'cpg.call.name(".*fieldAccess.*")' + self.to_cpg_traversal()

    def to_cpg_traversal(self) -> str:
        # arg(1) is the object, arg(2) is the field name
        return (
            f'.collectAll[nodes.Call].name(".*fieldAccess.*")'
            f".where(_.argument(1){self.receiver.to_cpg_traversal()})"
            f'.where(_.argument(2).filter(_.code.matches("{_esc(self.name)}")))'
        )


@dataclass
class Return(Pattern):
    """Matches a return statement."""

    def to_cpg(self) -> str:
        return "cpg.ret"

    def to_cpg_traversal(self) -> str:
        return ".isReturn"

    def to_scala_predicate(self, node_var: str) -> str:
        return f"{node_var}.isInstanceOf[nodes.Return]"


# Helper to allow simple strings in place of Identifier/Call where appropriate
PatternLike = Pattern | str
