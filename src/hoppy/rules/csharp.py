from ..core.rule import Confidence, ScanRule, Severity
from ..dsl.patterns import (
    Call,
    Field,
    Identifier,
    Method,
    Or,
    Parameter,
    Pattern,
    Var,
)
from ..dsl.query import Query
from .common import DynamicArg
from .discovery import DiscoveryHeuristic


def WebSource(var_name: str = "$IN") -> Pattern:
    """
    Matches untrusted web inputs for ASP.NET Core.
    """
    web_annotations = [
        "FromQuery",
        "FromBody",
        "FromRoute",
        "FromForm",
        "FromHeader",
        "FromServices",
    ]

    request_fields = r"(Query|Body|Cookies|Headers|Form)"

    return Or(
        [Parameter(name=var_name, annotation=a) for a in web_annotations]
        + [
            # ASP.NET Core: HttpRequest properties (field access or getter)
            Identifier(name="Request").field(request_fields),
            Call(fullname=r".*HttpRequest.get_" + request_fields + r".*"),
            # Fallback: Any parameter of a Controller method
            Parameter(name=var_name).inside(Controller()),
        ]
    )


def SqlSink() -> Pattern:
    """
    Matches SQL injection sinks in C# (Entity Framework, ADO.NET, Dapper).
    """
    # Non-literal string argument (likely a concatenated or interpolated string)
    arg = DynamicArg("$SQL")

    return Or(
        [
            # Entity Framework, Dapper, and generic execute methods with dynamic SQL
            Call(
                fullname=(
                    r".*(FromSql.*"
                    r"|ExecuteSql(Command|Raw|Interpolated).*"
                    r"|(SqlMapper|IDbConnection|DbConnection)\.(Query|Execute|QueryAsync|ExecuteAsync|ExecuteScalar).*"
                    r"|Execute(Reader|Scalar|NonQuery).*"
                    r"|(SqlCommand|SqliteCommand).*(<init>|CommandText).*)"
                ),
                args=[arg],
            ),
            # ADO.NET command execution (SQL text set on command object)
            Call(fullname=r".*SqlCommand\.Execute(Reader|Scalar|NonQuery|XmlReader).*"),
        ]
    )


def SsrfSink(coverage: str = "precision") -> Pattern:
    """
    Matches SSRF sinks in C#.
    """
    arg = DynamicArg("$URL")
    if coverage == "broad":
        return Call(
            fullname=r".*(HttpClient\..*|WebClient\..*|WebRequest\.Create|.*\.GetStringAsync).*",
            args=[arg],
        )
    return Call(
        fullname=r".*(HttpClient|WebClient)\..*(Get|Post|Send|Download|Create).*",
        args=[arg],
    )


def RceSink(coverage: str = "precision") -> Pattern:
    """
    Matches RCE sinks in C# (Process/PowerShell execution).
    """
    arg = DynamicArg("$CMD")
    if coverage == "broad":
        return Or(
            [
                Call(
                    fullname=r".*(Process\.Start|ProcessStartInfo\..*|PowerShell\.AddScript).*",
                    args=[arg],
                ),
                Call(fullname=r".*PowerShell\.Invoke.*"),
                # Match assignments to Arguments or FileName fields
                Call(
                    name="<operator>.assignment",
                    args=[
                        Field(receiver=Var("$ANY"), name=r"(Arguments|FileName)"),
                        arg,
                    ],
                ),
            ]
        )
    return Or(
        [
            Call(
                fullname=r".*(Process\.Start|PowerShell\.AddScript|ProcessStartInfo).*",
                args=[arg],
            ),
            # Match assignments to Arguments or FileName fields on likely process-related objects
            Call(
                name="<operator>.assignment",
                args=[Field(receiver=Var("$ANY"), name=r"(Arguments|FileName)"), arg],
            ),
        ]
    )


def PathTraversalSink(coverage: str = "precision") -> Pattern:
    """
    Matches path traversal sinks in C# (file/dir access).
    """
    arg = DynamicArg("$PATH")
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(File\.(ReadAllText|ReadAllBytes|WriteAllText|WriteAllBytes|Open|OpenRead|OpenWrite|Create)"
                r"|Directory\.(GetFiles|EnumerateFiles|CreateDirectory|Delete)"
                r"|FileInfo|DirectoryInfo).*"
            ),
            args=[arg],
        )
    return Call(
        fullname=(
            r".*(File\.(ReadAllText|ReadAllBytes|WriteAllText|WriteAllBytes|Open|OpenRead|OpenWrite|Create)"
            r"|Directory\.(GetFiles|EnumerateFiles|CreateDirectory|Delete)).*"
        ),
        args=[arg],
    )


def PathTraversalSanitizer() -> Pattern:
    """
    Matches path normalization/validation helpers in C#.
    """
    return Call(
        fullname=(
            r".*Path\.(GetFullPath|GetFileName|GetFileNameWithoutExtension|GetDirectoryName|Combine|Join).*"
        )
    )


def XmlSink() -> Pattern:
    """
    Matches XML injection sinks in C#.
    """
    return Call(
        fullname=r".*(XmlSerializer\.Deserialize|XmlDocument\.Load|XmlReader\.Create|.*\.LoadXml).*"
    )


def TemplateInjectionSink(coverage: str = "precision") -> Pattern:
    """
    Matches server-side template rendering sinks in C#.
    """
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(RazorEngine\.Run"
                r"|RazorLightEngine\.CompileRender"
                r"|Scriban\.Template\.Parse"
                r"|DotLiquid\.Template\.Parse).*"
            )
        )
    return Call(fullname=r".*(RazorEngine\.Run|RazorLightEngine\.CompileRender).*")


def OpenRedirectSink(coverage: str = "precision") -> Pattern:
    """
    Matches open redirect sinks in C#.
    """
    if coverage == "broad":
        return Call(fullname=(r".*(Redirect|RedirectPermanent|RedirectToAction|RedirectToRoute).*"))
    return Call(fullname=r".*(Redirect|RedirectToAction).*")


def OpenRedirectSanitizer() -> Pattern:
    """
    Matches local-url checks for redirect targets.
    """
    return Call(fullname=r".*(Url\.IsLocalUrl|LocalRedirect).*")


def InsecureCryptoSink(coverage: str = "precision") -> Pattern:
    """
    Matches weak cryptographic algorithm usage in C#.
    """
    if coverage == "broad":
        return Call(fullname=(r".*(MD5\.Create|SHA1\.Create|HMACMD5\.Create|SHA1Managed).*"))
    return Call(fullname=r".*(MD5\.Create|SHA1\.Create).*")


def ArchiveExtractionSink(coverage: str = "precision") -> Pattern:
    """
    Matches archive extraction APIs that can be vulnerable to Zip Slip.
    """
    arg = DynamicArg("$PATH")
    if coverage == "broad":
        return Call(
            fullname=r".*(ZipFile\.ExtractToDirectory|ZipArchive\.ExtractToDirectory).*",
            args=[arg],
        )
    return Call(fullname=r".*ZipFile\.ExtractToDirectory.*", args=[arg])


def UnsafePopulationSink() -> Pattern:
    """
    Matches mass assignment sinks in C#.
    """
    return Or(
        [
            Call(fullname=r".*ControllerBase\.(Try)?UpdateModelAsync.*"),
            Call(fullname=r".*Mapper\.Map.*"),
            Call(fullname=r".*IMapper\.Map.*"),
        ]
    )


def Controller() -> Pattern:
    """
    Matches methods that act as web endpoints in C#.
    """
    return Method(fullname=".*Controller.*") | Method(
        annotation=r"Route|HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|HttpHead|HttpOptions|ApiController"
    )


def AuthBarrier() -> Pattern:
    """
    Matches authentication checks in C#.
    """
    return Or(
        [
            Method(annotation=r"Authorize|AuthorizeJwtBearer"),
            Call(
                fullname=r".*(IsAuthenticated|HasPermission|checkAuth|VerifyToken|ValidateUser).*"
            ),
        ]
    )


def AuthBypass() -> Pattern:
    """
    Matches explicit authentication bypasses in C#.
    """
    return Method(annotation=r"AllowAnonymous|AllowUnauthenticated")


def get_scan_rules(coverage: str = "precision") -> list[ScanRule]:
    """
    Returns a list of common security scan rules for C#.
    """
    return [
        ScanRule(
            name="SQL Injection (Entity Framework)",
            query=Query.source(WebSource("$IN")).flows_to(SqlSink()),
            severity=Severity.high,
            root_cause="User input is directly concatenated into a SQL query string used with FromSql or ExecuteSqlCommand.",
            impact="An attacker can execute arbitrary SQL commands, potentially leading to unauthorized data access, modification, or deletion.",
        ),
        ScanRule(
            name="Server-Side Request Forgery (SSRF)",
            query=Query.source(WebSource("$IN")).flows_to(SsrfSink(coverage)),
            severity=Severity.high,
            root_cause="User-controlled URL is used in an HTTP client request without proper validation or restricted allowlist.",
            impact="An attacker can make the server perform requests to internal or external systems, potentially bypassing firewalls or accessing sensitive internal metadata services.",
        ),
        ScanRule(
            name="Insecure XML Deserialization / XXE",
            query=Query.source(WebSource("$IN")).flows_to(XmlSink()),
            severity=Severity.high,
            root_cause="Untrusted XML input is processed using insecurely configured XML parsers or serializers.",
            impact="An attacker can perform XML External Entity (XXE) attacks to read local files, perform SSRF, or cause Denial of Service (DoS).",
        ),
        ScanRule(
            name="Template Injection",
            query=Query.source(WebSource("$IN")).flows_to(TemplateInjectionSink(coverage)),
            severity=Severity.medium,
            root_cause="Untrusted input reaches a template rendering engine.",
            impact="Server-Side Template Injection (SSTI), potentially leading to RCE.",
        ),
        ScanRule(
            name="Open Redirect",
            query=Query.source(WebSource("$IN"))
            .flows_to(OpenRedirectSink(coverage))
            .passes_not(OpenRedirectSanitizer()),
            severity=Severity.medium,
            root_cause="User input is used in redirect targets without local-url validation.",
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
            name="RCE (Process / PowerShell)",
            query=Query.source(WebSource("$IN")).flows_to(RceSink(coverage)),
            severity=Severity.high,
            root_cause="User input reaches process execution or PowerShell invocation APIs.",
            impact="Remote Code Execution (RCE) on the server.",
        ),
        ScanRule(
            name="Path Traversal",
            query=Query.source(WebSource("$IN"))
            .flows_to(PathTraversalSink(coverage))
            .passes_not(PathTraversalSanitizer()),
            severity=Severity.high,
            root_cause="User-controlled path reaches file system APIs without validation.",
            impact="Unauthorized read/write of local files.",
        ),
        ScanRule(
            name="Archive Extraction (Zip Slip)",
            query=Query.source(WebSource("$IN")).flows_to(ArchiveExtractionSink(coverage)),
            severity=Severity.medium,
            root_cause="Archive extraction uses untrusted paths without validation.",
            impact="Arbitrary file overwrite during extraction (Zip Slip).",
        ),
        ScanRule(
            name="Unsafe Population (Mass Assignment)",
            query=Query.source(WebSource("$IN")).flows_to(UnsafePopulationSink()),
            severity=Severity.medium,
            confidence=Confidence.medium,
            root_cause="Untrusted input is used to populate multiple fields of an object at once.",
            impact="Unauthorized modification of sensitive fields.",
        ),
    ]


def get_barrier_heuristics() -> list[DiscoveryHeuristic]:
    """
    Returns authentication barrier heuristics for C#.
    """
    return [
        DiscoveryHeuristic(
            category="Auth Barrier",
            patterns=[
                r"(?i).*(Authorize|AuthorizeJwtBearer).*",
                r"(?i).*(IsAuthenticated|HasPermission|checkAuth|VerifyToken|ValidateUser).*",
            ],
        )
    ]


def get_discovery_heuristics() -> list[DiscoveryHeuristic]:
    """
    Returns discovery heuristics for C#.
    """
    return [
        DiscoveryHeuristic(
            category="Command Execution",
            patterns=[
                ".*System\\.Diagnostics\\.Process\\.Start.*",
                ".*System\\.Management\\.Automation\\.PowerShell\\.Invoke.*",
            ],
            weight=10,
            suspicious_params=["cmd", "command", "args", "shell", "script"],
        ),
        DiscoveryHeuristic(
            category="Database",
            patterns=[
                ".*Microsoft\\.EntityFrameworkCore.*ExecuteSql.*",
                ".*Microsoft\\.EntityFrameworkCore.*FromSql.*",
                ".*System\\.Data\\.SqlClient\\.SqlCommand\\.Execute.*",
                ".*Dapper\\.SqlMapper\\.Query.*",
            ],
            weight=9,
            suspicious_params=["sql", "query", "table", "where"],
        ),
        DiscoveryHeuristic(
            category="File System",
            patterns=[
                ".*System\\.IO\\.File\\.(Open|Read|Write|Delete|Copy|Move).*",
                ".*System\\.IO\\.Directory\\.(CreateDirectory|Delete|GetFiles|GetDirectories).*",
                ".*System\\.IO\\.FileInfo\\.(<init>).*",
                ".*System\\.IO\\.DirectoryInfo\\.(<init>).*",
            ],
            weight=7,
            suspicious_params=["path", "filename", "filepath", "dest", "src"],
        ),
        DiscoveryHeuristic(
            category="Network",
            patterns=[
                ".*System\\.Net\\.Http\\.HttpClient\\.(Get|Post|Put|Delete|Send|Request).*Async.*",
                ".*System\\.Net\\.WebRequest\\.Create.*",
                ".*System\\.Net\\.WebClient\\.(Download|Upload).*Async.*",
            ],
            weight=8,
            suspicious_params=["url", "host", "uri", "endpoint"],
        ),
        DiscoveryHeuristic(
            category="Code Injection",
            patterns=[
                ".*Microsoft\\.CodeAnalysis\\.CSharp\\.Scripting\\.CSharpScript\\.Evaluate.*",
                ".*System\\.Reflection\\.MethodInfo\\.Invoke.*",
            ],
            weight=10,
            suspicious_params=["code", "data", "expr", "payload"],
        ),
        DiscoveryHeuristic(
            category="Cryptography",
            patterns=[
                r".*(System\.Security\.Cryptography\.(HashAlgorithm|SymmetricAlgorithm|AsymmetricAlgorithm|KeyDerivation|PBKDF2)|Microsoft\.IdentityModel\.Tokens\.JsonWebTokenHandler|System\.IdentityModel\.Tokens\.Jwt\.JwtSecurityTokenHandler).*"
            ],
            weight=6,
            suspicious_params=["password", "secret", "key", "token", "hash", "salt"],
        ),
    ]
