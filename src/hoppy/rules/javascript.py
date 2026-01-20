from ..core.rule import Confidence, ScanRule, Severity
from ..dsl.patterns import (
    Call,
    Field,
    Identifier,
    Literal,
    Method,
    Or,
    Parameter,
    Pattern,
)
from ..dsl.query import Query
from .common import DynamicArg, Sanitizer


def WebSource(var_name: str = "$IN") -> Pattern:
    """
    Matches untrusted web inputs for JavaScript (Express/Koa).
    """
    request_fields = "body|query|params|headers|cookies|files"
    base_source = Identifier(name="req").field(request_fields) | Identifier(name="request").field(
        request_fields
    )
    ctx_source = Identifier(name="ctx").field("request|query|params|headers|state|body")

    return Or(
        [
            base_source,
            # Match deep field access (e.g. req.query.q)
            Field(receiver=base_source, name=".*"),
            ctx_source,
            Field(receiver=ctx_source, name=".*"),
            Parameter(name=var_name).inside(Controller()),
        ]
    )


def WebUrlSource(var_name: str = "$URL") -> Pattern:
    """
    Matches likely URL inputs for SSRF sinks in JavaScript.
    """
    url_fields = r".*(url|uri|host|target|dest|destination|redirect|next).*"
    req_container = Identifier(name="req").field("body|query|params|headers|cookies")
    req_direct = Identifier(name="req").field("originalUrl|url|path")
    request_direct = Identifier(name="request").field("originalUrl|url|path")
    ctx_container = Identifier(name="ctx").field("request|query|params|headers|state|body")

    return Or(
        [
            Field(receiver=req_container, name=url_fields),
            req_direct,
            request_direct,
            Field(receiver=ctx_container, name=url_fields),
            Field(receiver=ctx_container, name="originalUrl|url|path"),
            Parameter(name=url_fields).inside(Controller()),
        ]
    )


def RequestUrlSource() -> Pattern:
    """
    Matches request URL/path accessors often used in proxy handlers.
    """
    req_direct = Identifier(name="req").field("originalUrl|url|path")
    request_direct = Identifier(name="request").field("originalUrl|url|path")
    ctx_request = Identifier(name="ctx").field("request")
    ctx_direct = Field(receiver=ctx_request, name="originalUrl|url|path")
    return Or([req_direct, request_direct, ctx_direct])


def Controller() -> Pattern:
    """
    Matches web controller methods in JavaScript/TypeScript (NestJS, etc.).
    """
    http_decorators = r"(?i)(get|post|put|delete|patch|options|head|all)"
    return Method(annotation=http_decorators)


def AuthBarrier() -> Pattern:
    """
    Matches authentication checks in JavaScript.
    """
    guard_decorators = r"(?i)(UseGuards|AuthGuard|JwtAuthGuard|Roles|RoleGuard|PermissionGuard)"
    return Or(
        [
            Call(
                fullname=r".*(auth|authenticate|authorize|verifyToken|isAuthenticated|requireAuth).*"
            ),
            Method(annotation=guard_decorators),
        ]
    )


def AuthBypass() -> Pattern:
    """
    Matches explicit authentication bypasses in JavaScript.
    """
    bypass_decorators = r"(?i)(Public|AllowAnonymous|PermitAll|SkipAuth)"
    return Or(
        [
            Call(fullname=r".*(allowAnonymous|permitAll|skipAuth).*"),
            Method(annotation=bypass_decorators),
        ]
    )


def CommandSink() -> Pattern:
    """
    Matches OS command execution sinks in Node.js.
    """
    arg = DynamicArg("$CMD")
    return Call(
        fullname=(r".*child_process.*[:\.](exec|execSync|spawn|spawnSync|execFile|execFileSync).*"),
        args=[arg],
    )


def SqlSink(coverage: str = "precision") -> Pattern:
    """
    Matches SQL execution sinks in JavaScript.
    """
    arg = DynamicArg("$SQL")
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(sequelize.*[:\.]query"
                r"|knex.*[:\.](raw|whereRaw)"
                r"|pg.*[:\.]query"
                r"|mysql.*[:\.]query"
                r"|mariadb.*[:\.]query"
                r"|sqlite3.*[:\.](all|get|run)).*"
            ),
            args=[arg],
        )
    return Call(
        fullname=(
            r".*(sequelize.*[:\.]query"
            r"|knex.*[:\.]raw"
            r"|pg.*[:\.]query"
            r"|mysql.*[:\.]query"
            r"|mariadb.*[:\.]query"
            r"|sqlite3.*[:\.](all|get|run)).*"
        ),
        args=[arg],
    )


def StackedSqlSink() -> Pattern:
    """
    Matches SQL execution sinks that explicitly allow stacked queries in JavaScript.
    """
    arg = DynamicArg("$SQL")
    return Or(
        [
            Call(
                fullname=(
                    r".*(sqlite3.*[:\.]exec"
                    r"|better-sqlite3.*[:\.]exec"
                    r"|mssql.*[:\.]batch"
                    r"|tedious.*[:\.]execSqlBatch).*"
                ),
                args=[arg],
            ),
        ]
    )


def SsrfSink(coverage: str = "precision") -> Pattern:
    """
    Matches SSRF sinks in JavaScript.
    """
    arg = DynamicArg("$URL")
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(axios($|[:\.](get|post|put|delete|head|options|request))"
                r"|fetch"
                r"|node-fetch"
                r"|http.*[:\.](get|request)"
                r"|https.*[:\.](get|request)"
                r"|request[:\.].*"
                r"|superagent[:\.].*"
                r"|got[:\.].*).*"
            ),
            args=[arg],
        )
    return Call(
        fullname=(
            r".*(axios($|[:\.](get|post|put|delete|head|options|request))"
            r"|fetch"
            r"|node-fetch"
            r"|http.*[:\.](get|request)"
            r"|https.*[:\.](get|request)).*"
        ),
        args=[arg],
    )


def PathTraversalSink() -> Pattern:
    """
    Matches file system access sinks in Node.js.
    """
    arg = DynamicArg("$PATH")
    return Call(
        fullname=(
            r".*fs.*[:\.](readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream"
            r"|unlink|readdir|readdirSync|mkdir|mkdirSync|rmdir|rmdirSync|open|openSync).*"
        ),
        args=[arg],
    )


def PathTraversalSanitizer() -> Pattern:
    """
    Matches path normalization helpers in Node.js.
    """
    base_dir_names = r".*(base|root|dir|path|allowed|public|static|uploads).*"
    base_dir_identifier = Identifier(name=base_dir_names)
    base_dir_call = Call(fullname=r".*process.*[:\.](cwd).*")
    base_dir = base_dir_identifier | base_dir_call | Identifier(name="__dirname")
    multer_path = Field(receiver=Identifier(name="req").field("file|files"), name="path") | Field(
        receiver=Identifier(name="request").field("file|files"),
        name="path",
    )

    return Or(
        [
            Call(fullname=r".*path.*[:\.]basename.*"),
            Call(
                fullname=r".*(sanitize.*(path|filename)|safeJoin|pathIsInside|isPathInside|is-path-inside|path-is-inside).*"
            ),
            Call(name="startsWith", args=[base_dir]),
            Call(
                fullname=r".*path.*[:\.](resolve|join).*",
                args=[base_dir],
            ),
            multer_path,
        ]
    )


def CodeInjectionSink() -> Pattern:
    """
    Matches dynamic code execution sinks in JavaScript.
    """
    arg = DynamicArg("$CODE")
    return Call(
        fullname=r".*(eval|Function|vm.*[:\.]run(InNewContext|InContext|Script)).*",
        args=[arg],
    )


def DeserializationSink() -> Pattern:
    """
    Matches insecure deserialization sinks in JavaScript.
    """
    arg = DynamicArg("$DATA")
    return Call(
        fullname=r".*((node-serialize|serialize).*[:\.]unserialize|yaml.*[:\.]load).*",
        args=[arg],
    )


def TemplateInjectionSink(coverage: str = "precision") -> Pattern:
    """
    Matches server-side template rendering sinks in JavaScript.
    """
    arg = DynamicArg("$TPL")
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(ejs.*[:\.]render"
                r"|pug.*[:\.]render"
                r"|handlebars.*[:\.]compile"
                r"|mustache.*[:\.]render"
                r"|nunjucks.*[:\.]renderString).*"
            ),
            args=[arg],
        )
    return Call(
        fullname=r".*(ejs.*[:\.]render|handlebars.*[:\.]compile|nunjucks.*[:\.]renderString).*",
        args=[arg],
    )


def TemplateSourceSanitizer() -> Pattern:
    """
    Matches loading template sources from disk (reduces false positives).
    """
    return Call(fullname=r".*fs.*[:\.]readFile(Sync)?.*")


def OpenRedirectSink(coverage: str = "precision") -> Pattern:
    """
    Matches open redirect sinks in JavaScript.
    """
    arg = DynamicArg("$URL")
    if coverage == "broad":
        return Call(fullname=r".*[:\.]redirect.*", args=[arg])
    return Call(fullname=r".*[:\.]redirect.*", args=[arg])


def InsecureCryptoSink(coverage: str = "precision") -> Pattern:
    """
    Matches weak cryptographic algorithm usage in JavaScript.
    """
    if coverage == "broad":
        return Or(
            [
                Call(fullname=r".*crypto.*[:\.]createHash.*", args=[Literal("md5")]),
                Call(fullname=r".*crypto.*[:\.]createHash.*", args=[Literal("sha1")]),
                Call(fullname=r".*crypto.*[:\.]createHash.*", args=[Literal("md4")]),
            ]
        )
    return Or(
        [
            Call(fullname=r".*crypto.*[:\.]createHash.*", args=[Literal("md5")]),
            Call(fullname=r".*crypto.*[:\.]createHash.*", args=[Literal("sha1")]),
        ]
    )


def ArchiveExtractionSink(coverage: str = "precision") -> Pattern:
    """
    Matches archive extraction APIs that can be vulnerable to Zip Slip.
    """
    arg = DynamicArg("$PATH")
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(adm-zip.*[:\.]extractAllTo"
                r"|unzipper.*[:\.]Extract"
                r"|tar.*[:\.]extract"
                r"|tar-fs.*[:\.]extract).*"
            ),
            args=[arg],
        )
    return Call(fullname=r".*adm-zip.*[:\.]extractAllTo.*", args=[arg])


def UnsafePopulationSink() -> Pattern:
    """
    Matches mass assignment sinks in JavaScript.
    """
    return Or(
        [
            Call(fullname=r".*Object.*[:\.]assign.*"),
            Call(fullname=r".*lodash.*[:\.]merge.*"),
            Call(
                fullname=r".*_\.merge.*"
            ),  # _ is usually a var name, not module, but keeping as is or changing to :
        ]
    )


def PrototypePollutionSink(coverage: str = "precision") -> Pattern:
    """
    Matches prototype pollution sinks in JavaScript.
    """
    arg = DynamicArg("$KEY")
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(Object.*[:\.]assign|Object.*[:\.]defineProperty|Object.*[:\.]defineProperties"
                r"|lodash.*[:\.]merge|_\.merge|_\.defaultsDeep"
                r"|defaultsDeep|merge|extend|setWith|set|zipObjectDeep).*"
            ),
            args=[arg],
        )
    return Call(
        fullname=(
            r".*(Object.*[:\.]assign|Object.*[:\.]defineProperty|Object.*[:\.]defineProperties"
            r"|lodash.*[:\.]merge|_\.merge|_\.defaultsDeep).*"
        ),
        args=[arg],
    )


def PrototypePollutionSanitizer() -> Pattern:
    """
    Matches common prototype pollution guard checks.
    """
    return Call(fullname=r".*(hasOwnProperty|Object[:\.]hasOwn).*")


def get_scan_rules(coverage: str = "precision") -> list[ScanRule]:
    """
    Returns a list of common security scan rules for JavaScript.
    """
    source = WebSource("$IN")
    sanitizer = Sanitizer()

    return [
        ScanRule(
            name="Code Injection",
            query=Query.source(source).flows_to(CodeInjectionSink()).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="Untrusted input reaches eval, Function, or vm execution.",
            impact="Remote Code Execution (RCE) on the server.",
        ),
        ScanRule(
            name="Command Injection",
            query=Query.source(source).flows_to(CommandSink()).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="Untrusted input is passed to child_process execution APIs.",
            impact="Remote Code Execution (RCE) on the server.",
        ),
        ScanRule(
            name="SQL Injection",
            query=Query.source(source).flows_to(SqlSink(coverage)).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="Untrusted input is used to construct a SQL query.",
            impact="Unauthorized data access, modification, or deletion.",
        ),
        ScanRule(
            name="SQL Injection (Stacked Queries)",
            query=Query.source(source).flows_to(StackedSqlSink()).passes_not(sanitizer),
            severity=Severity.high,
            root_cause="Untrusted input reaches a SQL API that executes multiple statements.",
            impact="Attackers can chain statements (e.g., DROP/UPDATE) after the intended query.",
        ),
        ScanRule(
            name="Path Traversal",
            query=Query.source(source)
            .flows_to(PathTraversalSink())
            .passes_not(sanitizer | PathTraversalSanitizer()),
            severity=Severity.high,
            root_cause="Untrusted input reaches file system APIs without validation.",
            impact="Unauthorized reading or writing of local files.",
        ),
        ScanRule(
            name="Insecure Deserialization",
            query=Query.source(source).flows_to(DeserializationSink()),
            severity=Severity.high,
            root_cause="Untrusted data is deserialized using unsafe libraries.",
            impact="Remote Code Execution (RCE) on the server.",
        ),
        ScanRule(
            name="Server-Side Request Forgery (SSRF)",
            query=Query.source(WebUrlSource("$URL"))
            .flows_to(SsrfSink(coverage))
            .passes_not(sanitizer),
            severity=Severity.high,
            root_cause="Untrusted input controls the target of a server-side request.",
            impact="Internal network access or data exfiltration.",
        ),
        ScanRule(
            name="Proxy SSRF (Request URL Passthrough)",
            query=Query.source(SsrfSink(coverage).inside(Controller()).inside(RequestUrlSource())),
            severity=Severity.high,
            root_cause="A request URL/path is reused to build a server-side request target.",
            impact="Proxy endpoints can be abused for SSRF or credential leakage.",
        ),
        ScanRule(
            name="Template Injection",
            query=Query.source(source)
            .flows_to(TemplateInjectionSink(coverage))
            .passes_not(TemplateSourceSanitizer()),
            severity=Severity.medium,
            root_cause="Untrusted input reaches a template rendering engine.",
            impact="Server-Side Template Injection (SSTI), potentially leading to RCE.",
        ),
        ScanRule(
            name="Open Redirect",
            query=Query.source(source).flows_to(OpenRedirectSink(coverage)),
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
            query=Query.source(source).flows_to(ArchiveExtractionSink(coverage)),
            severity=Severity.medium,
            root_cause="Archive extraction uses untrusted paths without validation.",
            impact="Arbitrary file overwrite during extraction (Zip Slip).",
        ),
        ScanRule(
            name="Prototype Pollution",
            query=Query.source(source)
            .flows_to(PrototypePollutionSink(coverage))
            .passes_not(PrototypePollutionSanitizer()),
            severity=Severity.medium,
            confidence=Confidence.medium,
            root_cause="Untrusted input reaches object merge/assign helpers without key filtering.",
            impact="Potential privilege escalation or RCE via poisoned prototypes.",
        ),
        ScanRule(
            name="Unsafe Population (Mass Assignment)",
            query=Query.source(source).flows_to(UnsafePopulationSink()),
            severity=Severity.medium,
            confidence=Confidence.medium,
            root_cause="Untrusted input is used to populate multiple fields of an object at once.",
            impact="Unauthorized modification of sensitive fields.",
        ),
        ScanRule(
            name="Missing Authentication for Dangerous Sink",
            query=Query.source(
                (CommandSink() | SqlSink(coverage) | CodeInjectionSink() | SsrfSink(coverage))
                .inside(Controller())
                .is_not_dominated_by(AuthBarrier())
            ),
            severity=Severity.high,
            confidence=Confidence.medium,
            root_cause="A dangerous operation is reachable without an auth check.",
            impact="Unauthorized users may execute sensitive operations.",
        ),
    ]
