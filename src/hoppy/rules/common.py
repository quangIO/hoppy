from ..dsl.patterns import Call, Literal, Pattern, Var


def DynamicArg(name: str = "$ANY") -> Pattern:
    """Matches an argument that is not a literal."""
    return Var(name) & ~Literal("$_")


def Sanitizer() -> Pattern:
    """Matches common sanitization patterns across languages."""
    return Call(
        fullname=r".*(escape|sanitize|encode|quote|validate|check|basename|abspath|realpath).*"
    )
