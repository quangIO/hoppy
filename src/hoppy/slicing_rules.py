from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class SliceRule:
    name: str
    description: str
    sink_pattern: str
    languages: tuple[str, ...] = ()
    coverage: str = "precision"


_RULES: list[SliceRule] = [
    SliceRule(
        name="sql-exec",
        description="SQL execution calls (execute/executeQuery/executeUpdate).",
        sink_pattern=r".*(executeQuery|executeUpdate|execute)$",
        languages=("java", "csharp", "python", "javascript"),
        coverage="precision",
    ),
    SliceRule(
        name="orm-raw-sql",
        description="ORM raw SQL execution helpers (FromSql/createNativeQuery).",
        sink_pattern=r".*(FromSql|fromSql|FromSqlRaw|fromSqlRaw|createNativeQuery).*",
        languages=("java", "csharp", "javascript"),
        coverage="precision",
    ),
    SliceRule(
        name="command-exec",
        description="OS command execution calls (exec/system/spawn/popen).",
        sink_pattern=r".*(exec|system|spawn|popen).*",
        languages=("java", "csharp", "python", "javascript"),
        coverage="precision",
    ),
    SliceRule(
        name="ssrf-http",
        description="HTTP client requests that may be SSRF sinks.",
        sink_pattern=(
            r".*(http|get|post|put|delete|head|request|requests|"
            r"urlopen|openConnection|HttpClient|WebClient|RestTemplate|"
            r"OkHttpClient|HttpRequest|fetch|axios).*"
        ),
        languages=("java", "csharp", "python", "javascript"),
        coverage="broad",
    ),
    SliceRule(
        name="ssrf-http-precision",
        description="HTTP client calls that frequently act as SSRF sinks.",
        sink_pattern=(
            r".*(urlopen|openConnection|HttpClient|WebClient|RestTemplate|"
            r"OkHttpClient|HttpRequest|fetch|axios).*"
        ),
        languages=("java", "csharp", "python", "javascript"),
        coverage="precision",
    ),
    SliceRule(
        name="path-traversal",
        description="File access and path handling sinks (read/write/open).",
        sink_pattern=(
            r".*(open|read|write|FileInputStream|FileOutputStream|"
            r"FileReader|FileWriter|Files\\.|Path\\.|StreamReader|StreamWriter).*"
        ),
        languages=("java", "csharp", "python", "javascript"),
        coverage="broad",
    ),
    SliceRule(
        name="path-traversal-precision",
        description="File access calls likely to be path traversal sinks.",
        sink_pattern=(
            r".*(FileInputStream|FileOutputStream|Files\\.|Path\\.|"
            r"FileReader|FileWriter|open|read|write).*"
        ),
        languages=("java", "csharp", "python", "javascript"),
        coverage="precision",
    ),
    SliceRule(
        name="deserialization",
        description="Unsafe deserialization calls.",
        sink_pattern=(
            r".*(deserialize|readObject|ObjectInputStream|BinaryFormatter|"
            r"pickle|yaml\\.load|marshal\\.loads|XmlSerializer|DataContractSerializer).*"
        ),
        languages=("java", "csharp", "python", "javascript"),
        coverage="precision",
    ),
    SliceRule(
        name="xxe",
        description="XML parsing sinks that may allow XXE.",
        sink_pattern=(
            r".*(DocumentBuilder|SAXParser|XMLReader|XmlDocument|XmlReader|"
            r"XDocument|lxml\\.etree|ElementTree\\.parse).*"
        ),
        languages=("java", "csharp", "python", "javascript"),
        coverage="precision",
    ),
    SliceRule(
        name="template-injection",
        description="Template rendering/execution sinks (SSTI).",
        sink_pattern=(
            r".*(render|render_template|Template|jinja2|Freemarker|Velocity|"
            r"Thymeleaf|Razor|Liquid).*"
        ),
        languages=("java", "csharp", "python", "javascript"),
        coverage="precision",
    ),
    SliceRule(
        name="code-injection",
        description="Dynamic code execution sinks (eval/exec/compile).",
        sink_pattern=r".*(eval|exec|compile|CodeDom|Reflection|invoke).*",
        languages=("java", "csharp", "python", "javascript"),
        coverage="precision",
    ),
    SliceRule(
        name="open-redirect",
        description="Redirect sinks that may allow open redirects.",
        sink_pattern=r".*(redirect|sendRedirect|Location).*",
        languages=("java", "csharp", "python", "javascript"),
        coverage="broad",
    ),
    SliceRule(
        name="file-upload",
        description="File upload or write sinks (save/upload/transfer).",
        sink_pattern=r".*(save|upload|transferTo|WriteAllBytes|WriteAllText).*",
        languages=("java", "csharp", "python", "javascript"),
        coverage="precision",
    ),
]


CAPABILITIES = {
    "python": {
        "File System": (
            r"(?i).*(\bopen\b|\bread\b|\bwrite\b|pathlib\.|os\.path|tempfile\.|shutil\.).*"
        ),
        "Database": (
            r"(?i).*(execute|query|sql|mongo|redis|sqlalchemy|django\.db|psycopg2|sqlite3|"
            r"pymongo|db\.cursor).*"
        ),
        "Network": r"(?i).*(requests\.|urllib\.|http\.|socket\.|aiohttp\.|httpx\.|paramiko\.).*",
        "Command Execution": r"(?i).*(subprocess\.|os\.system|os\.popen|os\.spawn|shlex\.|pty\.).*",
        "Code Execution": (
            r"(?i).*(\beval\b|\bexec\b|load_string|run_code|InteractiveInterpreter|"
            r"compile\(|pickle\.|marshal\.).*"
        ),
        "Cryptography": (
            r"(?i).*(hashlib|Crypto|cryptography\.|hmac\.|secrets\.|JwtSecurityToken|"
            r"base64\.b64encode).*"
        ),
    },
    "java": {
        "File System": (
            r"(?i).*(java\.io\.(File|FileInputStream|FileOutputStream|FileReader|"
            r"FileWriter|RandomAccessFile)|java\.nio\.file\.Files\.(write|read|delete|"
            r"create|move|copy)|DocumentBuilder|SAXParser|XMLReader|Transformer|"
            r"org\.apache\.commons\.io).*"
        ),
        "Database": (
            r"(?i).*(execute|query|sql|mongo|redis|jdbc|hibernate|jpa|mybatis|"
            r"crudrepository|Jdbi).*"
        ),
        "Network": (
            r"(?i).*(java\.net\.(Http|Socket|URL)|javax\.net\.|jsoup|okhttp|"
            r"apache\.http|HttpClient|WebClient|RestTemplate|FeignClient|"
            r"spring-cloud-starter-openfeign).*"
        ),
        "Command Execution": r"(?i).*(ProcessBuilder|Runtime\.exec|os\.popen).*",
        "Code Execution": (
            r"(?i).*(eval\b|exec\b(?!uteQuery|uteUpdate)|ScriptEngine|GroovyShell|"
            r"PythonInterpreter|invokedynamic|Ognl).*"
        ),
        "Cryptography": (
            r"(?i).*(MessageDigest|Cipher|Signature|BCrypt|SCrypt|PBKDF2|"
            r"javax\.crypto|jsonwebtoken|Jwts|Jwt|Base64).*"
        ),
    },
    "javascript": {
        "File System": (
            r"(?i).*((fs[:\.]|fs/)(read|write|append|open|link|mkdir|rm|create|readdir|"
            r"unlink)|path[:\.]).*"
        ),
        "Database": (
            r"(?i).*(execute|query|sql|mongo|redis|sequelize|mongoose|knex|prisma|"
            r"pg-pool|pg[:\.]|mysql|mysql2|typeorm|createQueryBuilder|([a-z0-9]"
            r"(Repository|Repo|Model|Context|Db)[:\.](save|update|delete|insert|remove|"
            r"count|increment|decrement|find|get)(One|By|And|Many|All|Raw|AndCount)?\b)).*"
        ),
        "Network": (
            r"(?i).*(http[:\.]|socket[:\.]|axios|node-fetch|request[:\.]|fetch\b|got[:\.]|"
            r"superagent|nodemailer|([a-z0-9](Client|Http|Api)[:\.]"
            r"(get|post|put|delete|patch|head)\b)).*"
        ),
        "Command Execution": r"(?i).*(\bchild_process\b|\bexec\b|\bspawn\b).*",
        "Code Execution": (
            r"(?i).*(\beval\b|vm[:\.](runInContext|runInNewContext|"
            r"runInThisContext)|new Function\(|serialize-javascript).*"
        ),
        "Cryptography": r"(?i).*(crypto|bcrypt|scrypt|argon2|jsonwebtoken|\bjwt\b|\bsign\b).*",
    },
    "csharp": {
        "File System": (
            r"(?i).*(System\.IO\.(File|Directory|StreamWriter|StreamReader)|"
            r"XmlDocument|XmlSerializer|XmlReader|XDocument|XElement).*"
        ),
        "Database": (
            r"(?i).*(execute|query|sql|System\.Data|EntityFrameworkCore|FromSql|"
            r"ExecuteSqlCommand|DbSet|Where|FirstOrDefault|ToList|Any|Count).*"
        ),
        "Network": (
            r"(?i).*(System\.Net\.(Http|Socket|WebClient)|HttpClient|RestSharp|"
            r"WebRequest).*"
        ),
        "Command Execution": r"(?i).*(Diagnostics\.Process|System\.Management\.Automation).*",
        "Code Execution": (
            r"(?i).*(\beval\b|exec\b|CSharpCompilation|Assembly\.Load|"
            r"Reflection\.MethodInfo\.Invoke).*"
        ),
        "Cryptography": (
            r"(?i).*(System\.Security\.Cryptography|BCrypt|SCrypt|JwtSecurityToken|Jwt|"
            r"MD5|SHA1|SHA256|SymmetricSecurityKey|SigningCredentials|WriteToken|"
            r"FromBase64String|authorizeCreateAccessToken|createAccessToken).*"
        ),
    },
}


def get_capability_rules(language: str) -> dict[str, str]:
    """
    Returns capability regexes for a given language.
    """
    if not language:
        return {}
    lang = language.lower()
    return CAPABILITIES.get(lang, {})


def get_slicing_rules(language: str | None = None, coverage: str = "precision") -> list[SliceRule]:
    rules = list(_RULES)
    if coverage and coverage != "all":
        rules = [r for r in rules if r.coverage == coverage]
    if not language:
        return rules
    lang = language.lower()
    return [r for r in rules if not r.languages or lang in r.languages]


def get_slicing_rule(
    name: str, language: str | None = None, coverage: str = "precision"
) -> SliceRule | None:
    name_l = name.lower()
    for rule in get_slicing_rules(language, coverage=coverage):
        if rule.name.lower() == name_l:
            return rule
    return None


def format_rules(rules: Iterable[SliceRule]) -> list[str]:
    return [
        f"{r.name}: {r.description} (coverage: {r.coverage}, pattern: {r.sink_pattern})"
        for r in rules
    ]
