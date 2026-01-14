from ..core.rule import ScanRule, Severity
from ..dsl.patterns import (
    Call,
    Identifier,
    Literal,
    Method,
    Or,
    Parameter,
    Pattern,
    Var,
)
from ..dsl.query import Query
from .common import DynamicArg, Sanitizer


def WebSource(var_name: str = "$IN") -> Pattern:
    """
    Matches untrusted web inputs for Python (FastAPI/Flask/Django).
    """
    request_fields = (
        r"(GET|POST|FILES|COOKIES|META|headers|args|form|values|json|data|query_params)"
    )
    base_source = Identifier(name="request").field(request_fields)

    return Or(
        [
            # FastAPI/Flask parameters (excluding 'request' which is handled below)
            Parameter(name=var_name).where(~Parameter(name="request")),
            # Django/Flask request object fields
            base_source,
            # Index accesses on request fields (e.g. request.POST["url"])
            Call(name=r".*indexAccess.*", args=[base_source, Var("$IDX")]),
            # FastAPI Depends
            Call(name="Depends"),
        ]
    )


def Controller() -> Pattern:
    """
    Matches methods that act as web endpoints in Python (FastAPI/Flask/Django).
    """
    return Or(
        [
            Method(annotation=r"(get|post|put|delete|patch|route|login_required)"),
            # Django views often have names ending in _view or are in views.py
            Method(name=r".*_view"),
        ]
    )


def AuthBarrier() -> Pattern:
    """
    Matches authentication checks in Python.
    """
    return Or(
        [
            Call(fullname=r".*(auth|login|verify_token|check_perm|authenticate).*"),
            Call(name=r"(is_authenticated|check_password|authenticate)"),
            Method(annotation=r".*(auth|login|permission|requires_auth|restricted).*"),
            # Django/Flask style property checks
            Identifier(name="request").field("user").field("is_authenticated"),
            Identifier(name="user").field("is_authenticated"),
        ]
    )


def AuthBypass() -> Pattern:
    """
    Matches explicit authentication bypasses in Python.
    """
    return Method(annotation=r"(public|allow_anonymous|csrf_exempt)")


def CommandSink() -> Pattern:
    """
    Matches OS command execution sinks with dynamic arguments.
    """
    arg = DynamicArg("$CMD")
    return Or(
        [
            Call(
                fullname=r".*subprocess.*\.(run|call|check_call|check_output|Popen).*",
                args=[arg],
            ),
            Call(fullname=r".*os.*\.(system|popen|spawn.*|exec.*).*", args=[arg]),
        ]
    )


def SqlSink() -> Pattern:
    """
    Matches SQL execution sinks with dynamic arguments.
    """
    arg = DynamicArg("$SQL")
    return Or(
        [
            Call(name=r"(execute|raw)", args=[arg]),
            Call(
                fullname=r".*(django\.db\.models\.query\.QuerySet\.raw|django\.db\.connection\.cursor).*"
            ),
        ]
    )


def PathTraversalSink() -> Pattern:
    """
    Matches file system access sinks with dynamic arguments.
    """
    arg = DynamicArg("$PATH")
    return Or(
        [
            Call(name="open", args=[arg]),
            Call(
                fullname=r".*(os.*\.(open|listdir|remove|rmdir|mkdir|makedirs)|shutil.*\.(copy|move)).*",
                args=[arg],
            ),
            Call(
                fullname=r".*django\.core\.files\.storage\.Storage\.(save|open).*",
                args=[None, arg],
            ),
        ]
    )


def PathTraversalSanitizer() -> Pattern:
    """
    Matches path normalization or allow-list helpers in Python.
    """
    return Or(
        [
            Call(
                fullname=(
                    r".*(os\.path.*\.(abspath|realpath|normpath|basename)"
                    r"|pathlib\.Path.*\.(resolve|absolute)).*"
                )
            ),
            Call(name="basename"),
        ]
    )


def DeserializationSink() -> Pattern:
    """
    Matches insecure deserialization sinks.
    """
    arg = DynamicArg("$DATA")
    return Call(
        fullname=(
            r".*((pickle|_pickle|marshal).*\.(loads|load)"
            r"|yaml.*\.(load|load_all|unsafe_load)).*"
        ),
        args=[arg],
    )


def SsrfSink() -> Pattern:
    """
    Matches SSRF sinks.
    """
    arg = DynamicArg("$URL")
    return Call(
        fullname=(
            r".*(requests.*\.(get|post|put|delete|patch|head|options|request)"
            r"|urllib\.request.*\.urlopen"
            r"|aiohttp\.ClientSession.*).*"
        ),
        args=[arg],
    )


def TemplateInjectionSink(coverage: str = "precision") -> Pattern:
    """
    Matches server-side template rendering sinks in Python.
    """
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(jinja2\.Template.*\.render"
                r"|jinja2\.Environment.*\.from_string"
                r"|flask.*\.render_template_string"
                r"|django\.template\.Template"
                r"|django\.template\.loader\.render_to_string"
                r"|django\.shortcuts\.render).*"
            )
        )
    return Call(
        fullname=r".*(jinja2\.Environment.*\.from_string|flask.*\.render_template_string|django\.template\.Template).*"
    )


def OpenRedirectSink(coverage: str = "precision") -> Pattern:
    """
    Matches open redirect sinks in Python.
    """
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(flask.*\.redirect"
                r"|django\.shortcuts\.redirect"
                r"|django\.http\.HttpResponseRedirect"
                r"|starlette\.responses\.RedirectResponse"
                r"|fastapi\.responses\.RedirectResponse).*"
            )
        )
    return Call(
        fullname=r".*(flask.*\.redirect|django\.shortcuts\.redirect|django\.http\.HttpResponseRedirect|fastapi\.responses\.RedirectResponse).*"
    )


def OpenRedirectSanitizer() -> Pattern:
    """
    Matches local/allowed-host checks for redirect targets.
    """
    return Call(fullname=r".*(is_safe_url|url_has_allowed_host_and_scheme).*")


def InsecureCryptoSink(coverage: str = "precision") -> Pattern:
    """
    Matches weak cryptographic algorithm usage in Python.
    """
    if coverage == "broad":
        return Or(
            [
                Call(fullname=r".*hashlib\.(md5|sha1).*"),
                Call(fullname=r".*hashlib\.new.*", args=[Literal(r"(md5|sha1)")]),
                Call(fullname=r".*Crypto\.Cipher\.(AES|DES|ARC4).*"),
            ]
        )
    return Call(fullname=r".*hashlib\.(md5|sha1).*")


def ArchiveExtractionSink(coverage: str = "precision") -> Pattern:
    """
    Matches archive extraction APIs that can be vulnerable to Zip Slip.
    """
    arg = DynamicArg("$PATH")
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(zipfile\.ZipFile\.extractall"
                r"|tarfile\.TarFile\.extractall"
                r"|shutil\.unpack_archive).*"
            ),
            args=[arg],
        )
    return Call(
        fullname=r".*zipfile\.ZipFile\.extractall.*",
        args=[arg],
    )


def UnsafePopulationSink() -> Pattern:
    """
    Matches mass assignment sinks where multiple fields are populated at once.
    """
    return Or(
        [
            # SQLAlchemy/Django: model.update(**data)
            Call(name="update", args=[Var("$DATA")]),
            # Pydantic/FastAPI: Model.parse_obj(data)
            Call(name=r"(parse_obj|from_orm)", args=[Var("$DATA")]),
        ]
    )


def CodeInjectionSink() -> Pattern:
    """
    Matches dynamic code execution sinks with dynamic arguments.
    """
    arg = DynamicArg("$CODE")
    return Or(
        [
            Call(name=r"(exec|eval)", args=[arg]),
            Call(fullname=r".*ImageMath\.eval.*", args=[arg]),
            Call(fullname=r".*code\.Interactive.*"),
        ]
    )


def get_scan_rules(coverage: str = "precision") -> list[ScanRule]:
    """
    Returns a list of common security scan rules for Python.
    """
    source = WebSource("$IN")
    sanitizer = Sanitizer()
    auth_annotation = r".*(auth|login|permission|requires_auth|restricted).*"

    return [
        ScanRule(
            name="Code Injection",
            query=Query.source(source).flows_to(CodeInjectionSink()).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="Untrusted input is passed to a dynamic code execution function like exec() or eval().",
            impact="Full Remote Code Execution (RCE) on the server.",
        ),
        ScanRule(
            name="Command Injection",
            query=Query.source(source).flows_to(CommandSink()).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="Untrusted input is passed to a system command execution function.",
            impact="Remote Code Execution (RCE) on the server.",
        ),
        ScanRule(
            name="SQL Injection",
            query=Query.source(source).flows_to(SqlSink()).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="Untrusted input is used to construct a SQL query.",
            impact="Unauthorized data access, modification, or deletion.",
        ),
        ScanRule(
            name="Path Traversal",
            query=Query.source(source)
            .flows_to(PathTraversalSink())
            .passes_not(sanitizer | PathTraversalSanitizer()),
            severity=Severity.high,
            root_cause="Untrusted input is used in file system operations without proper validation or sanitization.",
            impact="Unauthorized reading or writing of local files.",
        ),
        ScanRule(
            name="Insecure Deserialization",
            query=Query.source(source).flows_to(DeserializationSink()),
            severity=Severity.high,
            root_cause="Untrusted data is deserialized using insecure libraries like pickle.",
            impact="Remote Code Execution (RCE) on the server.",
        ),
        ScanRule(
            name="Server-Side Request Forgery (SSRF)",
            query=Query.source(source).flows_to(SsrfSink()).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="Untrusted input is used to determine the target of a server-side network request.",
            impact="Internal network scanning, unauthorized access to internal services or metadata.",
        ),
        ScanRule(
            name="Template Injection",
            query=Query.source(source).flows_to(TemplateInjectionSink(coverage)),
            severity=Severity.medium,
            root_cause="Untrusted input reaches a template rendering engine.",
            impact="Server-Side Template Injection (SSTI), potentially leading to RCE.",
        ),
        ScanRule(
            name="Open Redirect",
            query=Query.source(source)
            .flows_to(OpenRedirectSink(coverage))
            .passes_not(OpenRedirectSanitizer()),
            severity=Severity.medium,
            root_cause="User input is used in redirect targets without validation.",
            impact="Phishing, token leakage, and open redirect abuse.",
        ),
        ScanRule(
            name="Weak Cryptography",
            query=Query.source(InsecureCryptoSink(coverage)),
            severity=Severity.medium,
            root_cause="Weak hashing algorithms (MD5/SHA1) are used for sensitive data.",
            impact="Hash collisions and offline cracking.",
        ),
        ScanRule(
            name="Archive Extraction (Zip Slip)",
            query=Query.source(source)
            .flows_to(ArchiveExtractionSink(coverage))
            .passes_not(PathTraversalSanitizer()),
            severity=Severity.medium,
            root_cause="Archive entries are extracted without path normalization.",
            impact="Arbitrary file overwrite during extraction (Zip Slip).",
        ),
        ScanRule(
            name="Unsafe Population (Mass Assignment)",
            query=Query.source(source).flows_to(UnsafePopulationSink()),
            severity=Severity.medium,
            root_cause="Untrusted input is used to populate multiple fields of an object at once, which can lead to unauthorized modification of sensitive fields.",
            impact="An attacker may be able to modify fields they shouldn't have access to (e.g., is_admin).",
        ),
        ScanRule(
            name="Missing Authentication for Dangerous Sink",
            query=Query.source(
                (CommandSink() | SqlSink() | PathTraversalSink() | CodeInjectionSink())
                .is_not_dominated_by(AuthBarrier())
                .inside(~Method(annotation=auth_annotation))
            ),
            severity=Severity.high,
            root_cause="A dangerous operation is performed without being preceded by an authentication check.",
            impact="Unauthorized users may be able to perform dangerous actions.",
        ),
    ]
