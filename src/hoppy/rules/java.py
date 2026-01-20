from ..core.rule import Confidence, ScanRule, Severity
from ..dsl.patterns import Call, Literal, Method, Or, Parameter, Pattern, Return
from ..dsl.query import Query
from .common import DynamicArg


def WebSource(var_name: str = "$IN") -> Pattern:
    """
    Matches untrusted web inputs for Java frameworks (Spring, etc.).
    """
    web_annotations = [
        "RequestParam",
        "RequestBody",
        "PathVariable",
        "RequestHeader",
        "QueryParam",
        "PathParam",
        "HeaderParam",
        "CookieParam",
        "FormParam",
        "MatrixParam",
    ]

    return Or(
        [Parameter(name=var_name, annotation=a) for a in web_annotations]
        + [
            # Fallback: Any parameter of a Controller method
            Parameter(name=var_name).inside(Controller()),
        ]
    )


def SqlSink(coverage: str = "precision") -> Pattern:
    """
    Matches SQL injection sinks in Java (JDBC, JdbcTemplate).
    """
    arg = DynamicArg("$SQL")
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(Statement\.execute(Query|Update)?"
                r"|JdbcTemplate\.query"
                r"|JdbcTemplate\.update"
                r"|EntityManager\.(createNativeQuery|createQuery|createNamedQuery|createStoredProcedureQuery)"
                r"|Session\.(createSQLQuery|createQuery|createNativeQuery)).*"
            ),
            args=[arg],
        )
    return Call(
        fullname=(
            r".*(Statement\.execute(Query|Update)?"
            r"|JdbcTemplate\.query"
            r"|JdbcTemplate\.update"
            r"|EntityManager\.createNativeQuery"
            r"|Session\.createSQLQuery).*"
        ),
        args=[arg],
    )


def CommandSink() -> Pattern:
    """
    Matches command injection sinks in Java.
    """
    arg = DynamicArg("$CMD")
    return Call(fullname=r".*(ProcessBuilder\.command|Runtime\.exec).*", args=[arg])


def SsrfSink(coverage: str = "precision") -> Pattern:
    """
    Matches SSRF sinks in Java.
    """
    arg = DynamicArg("$URL")
    if coverage == "broad":
        return Call(
            fullname=(
                r".*((HttpClient|RestTemplate|OkHttpClient|WebClient|URLConnection|HttpURLConnection)\..*"
                r"|.*\.connect"
                r"|URL\.openStream"
                r"|URL\.openConnection).*"
            ),
            args=[arg],
        )
    return Call(
        fullname=(
            r".*(Jsoup\.connect"
            r"|HttpClient\..*"
            r"|RestTemplate\..*"
            r"|OkHttpClient\..*"
            r"|URLConnection\.connect"
            r"|HttpURLConnection\.connect"
            r"|URL\.openStream"
            r"|URL\.openConnection).*"
        ),
        args=[arg],
    )


def XxeSink(coverage: str = "precision") -> Pattern:
    """
    Matches XML parsers vulnerable to XXE.
    """
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(DocumentBuilderFactory\.newDocumentBuilder"
                r"|SAXParserFactory\.newSAXParser"
                r"|XMLInputFactory\.newXMLStreamReader"
                r"|DocumentBuilder\.parse"
                r"|SAXParser\.parse"
                r"|XMLReader\.parse).*"
            )
        )
    return Call(
        fullname=(
            r".*(DocumentBuilderFactory\.newDocumentBuilder"
            r"|SAXParserFactory\.newSAXParser"
            r"|XMLInputFactory\.newXMLStreamReader).*"
        )
    )


def XxeSanitizer() -> Pattern:
    """
    Matches hardening calls for XML parsers.
    """
    return Call(fullname=r".*(setFeature|setProperty|setXIncludeAware|setExpandEntityReferences).*")


def DeserializationSink(coverage: str = "precision") -> Pattern:
    """
    Matches unsafe deserialization sinks.
    """
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(ObjectInputStream\.(readObject|readUnshared)"
                r"|ObjectInput\.(readObject|readUnshared)"
                r"|XMLDecoder\.readObject).*"
            )
        )
    return Call(fullname=r".*(ObjectInputStream\.readObject|XMLDecoder\.readObject).*")


def DeserializationSanitizer() -> Pattern:
    """
    Matches deserialization allow-list or filtering APIs.
    """
    return Call(
        fullname=r".*(ObjectInputFilter|ValidatingObjectInputStream|SafeObjectInputStream).*"
    )


def TemplateInjectionSink(coverage: str = "precision") -> Pattern:
    """
    Matches server-side template rendering sinks in Java.
    """
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(Template\.process"
                r"|VelocityEngine\.evaluate"
                r"|Velocity\.evaluate"
                r"|StringTemplate\.render"
                r"|SpringTemplateEngine\.process).*"
            )
        )
    return Call(fullname=r".*(Template\.process|SpringTemplateEngine\.process).*")


def OpenRedirectSink(coverage: str = "precision") -> Pattern:
    """
    Matches open redirect sinks in Java.
    """
    if coverage == "broad":
        return Call(fullname=r".*(sendRedirect|RedirectView).*")
    return Call(fullname=r".*sendRedirect.*")


def InsecureCryptoSink(coverage: str = "precision") -> Pattern:
    """
    Matches weak cryptographic algorithm usage in Java.
    """
    if coverage == "broad":
        return Or(
            [
                Call(
                    fullname=r".*MessageDigest\.getInstance.*",
                    args=[Literal("MD5")],
                ),
                Call(
                    fullname=r".*MessageDigest\.getInstance.*",
                    args=[Literal("SHA1")],
                ),
                Call(
                    fullname=r".*MessageDigest\.getInstance.*",
                    args=[Literal("MD2")],
                ),
            ]
        )
    return Or(
        [
            Call(fullname=r".*MessageDigest\.getInstance.*", args=[Literal("MD5")]),
            Call(fullname=r".*MessageDigest\.getInstance.*", args=[Literal("SHA1")]),
        ]
    )


def ArchiveExtractionSink(coverage: str = "precision") -> Pattern:
    """
    Matches archive extraction APIs that can be vulnerable to Zip Slip.
    """
    if coverage == "broad":
        return Call(
            fullname=(
                r".*(ZipInputStream\.getNextEntry"
                r"|ZipFile\.getEntry"
                r"|TarArchiveInputStream\.getNextTarEntry"
                r"|ArchiveStreamFactory\.createArchiveInputStream).*"
            )
        )
    return Call(fullname=r".*(ZipInputStream\.getNextEntry|ZipFile\.getEntry).*")


def ArchiveExtractionSanitizer() -> Pattern:
    """
    Matches common path canonicalization checks during extraction.
    """
    return Call(fullname=r".*(getCanonicalPath|normalize|toRealPath).*")


def UnsafePopulationSink() -> Pattern:
    """
    Matches mass assignment sinks in Java.
    """
    return Or(
        [
            Call(fullname=r".*BeanUtils\.copyProperties.*"),
            Call(fullname=r".*ModelMapper\.map.*"),
            Call(fullname=r".*PropertyUtils\.copyProperties.*"),
        ]
    )


def DbSource() -> Pattern:
    """Matches data retrieved from a database in Java."""
    return Call(
        fullname=".*ResultSet.get.*|.*EntityManager.find.*",
    )


def StorageSink() -> Pattern:
    """
    Matches sinks that store data in a database in Java.
    Useful for Stored XSS or other second-order vulnerabilities.
    """
    return Call(
        fullname=".*PreparedStatement.setString.*|.*PreparedStatement.setObject.*|.*JdbcTemplate.update.*",
    ).inside(Method(name="create|insert|save|update|commit"))


def ControllerReturn() -> Pattern:
    """
    Matches return values from Controller methods in Java (Spring).
    Useful for identifying Reflected XSS.
    """
    return Return().inside(Controller())


def Controller() -> Pattern:
    """
    Matches methods that act as web endpoints in Java.
    """
    return Method(fullname=".*Controller.*") | Method(
        annotation=r"RequestMapping|GetMapping|PostMapping|PatchMapping|DeleteMapping|PutMapping|RestController|Controller|MessageMapping|Path|GET|POST|PUT|DELETE|PATCH|Produces|Consumes"
    )


def AuthBarrier() -> Pattern:
    """
    Matches authentication checks in Java.
    """
    return Or(
        [
            Call(
                fullname=r".*(assertAuth|checkAuth|isAuthorized|isAuthenticated|hasPermission|verifyToken|validateUser).*"
            ),
            Method(
                annotation=r"PreAuthorize|Secured|RolesAllowed|RequiresAuthentication|RequiresPermissions|Authorize|Authenticated"
            ),
        ]
    )


def AuthBypass() -> Pattern:
    """
    Matches explicit authentication bypasses in Java.
    """
    return Method(annotation=r"PermitAll|AnonymousAllowed|Unauthenticated")


def get_scan_rules(coverage: str = "precision") -> list[ScanRule]:
    """
    Returns a list of common security scan rules for Java.
    """
    rules = [
        ScanRule(
            name="SQL Injection",
            query=Query.source(WebSource("$IN")).flows_to(SqlSink(coverage)),
            severity=Severity.high,
            root_cause="User input is directly used in SQL statements via Statement.execute or JdbcTemplate.query.",
            impact="Full database compromise, data theft, or destruction.",
        ),
        ScanRule(
            name="Command Injection",
            query=Query.source(WebSource("$IN")).flows_to(CommandSink()),
            severity=Severity.high,
            root_cause="User input is passed to system command executors like Runtime.exec or ProcessBuilder.",
            impact="Remote Code Execution (RCE) on the host server.",
        ),
        ScanRule(
            name="Stored XSS (Flow to Storage)",
            query=Query.source(WebSource("$IN")).flows_to(StorageSink()),
            severity=Severity.medium,
            confidence=Confidence.medium,
            root_cause="User input is saved to the database and later retrieved and rendered without escaping.",
            impact="Persistent Cross-Site Scripting affecting all users who view the malicious content.",
        ),
        ScanRule(
            name="Stored XSS (Flow to Output)",
            query=Query.source(DbSource()).flows_to(ControllerReturn()),
            severity=Severity.medium,
            confidence=Confidence.medium,
            root_cause="Data retrieved from the database is rendered in a controller response without escaping.",
            impact="Persistent Cross-Site Scripting when malicious data has been previously stored.",
        ),
        ScanRule(
            name="Weak Cryptography",
            query=Query.source(InsecureCryptoSink(coverage)),
            severity=Severity.medium,
            root_cause="Weak hashing algorithms (MD5/SHA1) are used for sensitive data.",
            impact="Hash collisions and offline cracking.",
        ),
        ScanRule(
            name="SSRF",
            query=Query.source(WebSource("$IN")).flows_to(SsrfSink(coverage)),
            severity=Severity.medium,
            root_cause="User input influences the target of a server-side network connection.",
            impact="Internal network scanning, metadata access, or interaction with internal services.",
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
            query=Query.source(WebSource("$IN")).flows_to(OpenRedirectSink(coverage)),
            severity=Severity.medium,
            root_cause="User input is used in redirect targets without allowlist validation.",
            impact="Phishing, token leakage, and open redirect abuse.",
        ),
        ScanRule(
            name="XXE",
            query=Query.source(WebSource("$IN"))
            .flows_to(XxeSink(coverage))
            .passes_not(XxeSanitizer()),
            severity=Severity.high,
            root_cause="User-controlled XML is parsed by an XML parser without secure configuration.",
            impact="XML External Entity (XXE) leading to file disclosure, SSRF, or DoS.",
        ),
        ScanRule(
            name="Insecure Deserialization",
            query=Query.source(WebSource("$IN"))
            .flows_to(DeserializationSink(coverage))
            .passes_not(DeserializationSanitizer()),
            severity=Severity.high,
            root_cause="Untrusted data is deserialized using Java serialization APIs.",
            impact="Remote Code Execution (RCE) or data integrity compromise.",
        ),
        ScanRule(
            name="Archive Extraction (Zip Slip)",
            query=Query.source(WebSource("$IN"))
            .flows_to(ArchiveExtractionSink(coverage))
            .passes_not(ArchiveExtractionSanitizer()),
            severity=Severity.medium,
            root_cause="Archive entries are extracted without path normalization or canonicalization.",
            impact="Arbitrary file overwrite during extraction (Zip Slip).",
        ),
        ScanRule(
            name="Unsafe Population (Mass Assignment)",
            query=Query.source(WebSource("$IN")).flows_to(UnsafePopulationSink()),
            severity=Severity.medium,
            root_cause="Untrusted input is used to populate multiple fields of an object at once.",
            impact="Unauthorized modification of sensitive fields.",
        ),
    ]

    if coverage == "broad":
        rules.append(
            ScanRule(
                name="Reflected XSS",
                query=Query.source(WebSource("$IN")).flows_to(ControllerReturn()),
                severity=Severity.medium,
                root_cause="User input is directly returned in a controller response without proper escaping.",
                impact="Execution of arbitrary JavaScript in the user's browser.",
            )
        )

    return rules
