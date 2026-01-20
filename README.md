# hoppy

hoppy is a security analysis tool for codebases. It sits on top of [Joern](https://joern.io/) and gives you a Python interface for writing code property graph (CPG) queries to find security vulnerabilities, data flows, and code patterns.

It supports C#, Java, JavaScript, and Python.

## What it actually does

 hoppy is basically a grep that understands code structure. Instead of regex matching on raw text, it queries a graph representation of your code that knows about:

- Control flow (what happens after this if statement)
- Data flow (where does this variable end up)
- Call graphs (who calls this function)
- Type information (what type is this variable)

This lets you ask questions like "show me all data flowing from web requests to SQL queries" and get actual answers instead of pattern matches.

## Quick Start

```bash
# Install hoppy with uv (recommended)
uvx --from git+https://github.com/quangio/hoppy hoppy scan ./path/to/code --lang python

# Or install from git with uv
uv pip install git+https://github.com/quangio/hoppy.git

# Or install from git with pip
pip install git+https://github.com/quangio/hoppy.git

# Run a security scan on your code
hoppy scan ./path/to/code --lang python

# Or use it as a library
uv run --from git+https://github.com/quangio/hoppy python - <<'EOF'
from hoppy import Analyzer, Query, Call, Var

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")
    q = Query.source(Var("$IN")).flows_to(Call(name="sink"))
    results = analyzer.execute(q)
    for match in results:
        print(f"{match.file}:{match.line} - {match.code}")
EOF
```

## Installation

### Requirements

- **Python 3.12+** - The project uses modern Python features and type hints.
- **uv** (recommended) - Fast Python package installer: https://github.com/astral-sh/uv

### How Hoppy Installs Joern

Hoppy automatically downloads and installs Joern to `~/.joern` on first run. No manual installation required.

- Joern is downloaded from the official releases
- Installation is automatic and requires no manual intervention
- Joern is installed to a well-known directory that doesn't require root privileges

If you already have Joern installed and in your PATH, Hoppy will use that version instead.

### Development Installation

```bash
git clone https://github.com/quangio/hoppy.git
cd hoppy
uv sync
```

## CLI Usage

hoppy has two main commands:

### `hoppy scan` - Security scanning

Performs deep taint analysis to find security vulnerabilities:

```bash
# Scan all languages
hoppy scan ./src

# Scan specific language
hoppy scan ./src --lang java

# Output SARIF for CI/CD
hoppy scan ./src --sarif results.sarif

# Filter by severity
hoppy scan ./src --min-severity high

# Only map attack surface (skip deep scans)
hoppy scan ./src --surface-only
```

### `hoppy slice` - Program slicing

Discover potential bug sources by slicing backwards from sink functions:

```bash
# List available slicing rules
hoppy slice --list-rules

# Slice using a named rule
hoppy slice ./src --rule sql-injection

# Slice with custom sink pattern
hoppy slice ./src --sink "execute.*query"

# Adjust depth and output
hoppy slice ./src --sink "eval" --depth 20 --max-sinks 10
```

### `hoppy list-methods` - Discovery

Lists methods and calls to discover dangerous sinks:

```bash
# List all method definitions
hoppy list-methods ./src

# List all called methods
hoppy list-methods ./src --calls

# List only external/library calls (API summary)
hoppy list-methods ./src --external

# Filter by regex
hoppy list-methods ./src --calls --pattern "execute"
```

## Python API

The real power is using hoppy as a library to write custom queries:

```python
from hoppy import Analyzer, Query, Call, Var, rules

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Use predefined rules for common patterns
    q = Query.source(rules.WebSource()).flows_to(rules.SqlSink())
    results = analyzer.execute(q)

    for match in results:
        print(f"{match.file}:{match.line}")
        if match.flow:
            for element in match.flow:
                print(f"  -> {element.file}:{element.line}: {element.code}")
```

### Building custom queries

hoppy provides a DSL for constructing queries:

```python
from hoppy import Query, Call, Literal, Identifier, And, Or, Not

# Match specific function calls
q = Query.source(Call(name="dangerous_func"))

# Match with argument patterns
q = Query.source(Call(name="execute", args=[Literal("$X")]))

# Compose patterns
pattern = And([
    Call(name="process"),
    Call(receiver_type="UserInput")
])

# Multi-step data flows
q = (Query.source(Call(name="get_input"))
     .flows_to(Call(name="sanitize"))
     .flows_to(Call(name="execute")))

# With sanitizers (flows that DON'T pass through)
q = (Query.source(rules.WebSource())
     .flows_to(rules.CommandSink())
     .passes_not(rules.Sanitizer()))
```

### Pattern types

- `Call(name="func")` - Function/method calls
- `Literal("value")` - Literal values (or `Literal("$X")` for metavariables)
- `Identifier("var")` - Variable references
- `Method(name="func")` - Method definitions
- `Field(name="field")` - Field accesses
- `Var("$X")` - Wildcard (matches anything)
- `And([p1, p2])` / `Or([p1, p2])` / `Not(p)` - Logical composition
- `Inside(pattern)` - Match within a context (e.g., method)
- `DominatedBy(pattern)` - Match preceded by pattern in control flow

## Built-in rules

hoppy comes with predefined security rules for common vulnerability patterns:

### Sources (untrusted input)
- `rules.WebSource()` - Web requests, route parameters, form data
- `rules.FileSystemSource()` - File reads
- `rules.EnvironmentSource()` - Environment variables

### Sinks (dangerous operations)
- `rules.SqlSink()` - SQL execution
- `rules.CommandSink()` - Command execution
- `rules.SsrfSink()` - HTTP requests (SSRF)
- `rules.XmlSink()` - XML parsing (XXE)
- `rules.PathTraversalSink()` - File system operations
- `rules.DeserializationSink()` - Deserialization

### Helpers
- `rules.Controller()` - Identifies web endpoints
- `rules.AuthBarrier()` - Identifies authentication checks
- `rules.Sanitizer()` - Common sanitization functions

## How it works

1. **Joern parses your code** into a Code Property Graph (AST + CFG + dataflow)
2. **hoppy translates Python queries** into Scala that Joern understands
3. **Joern executes the query** and returns results as JSON
4. **hoppy parses the JSON** into Python objects with file/line/code info

The translation layer is the key - you write Python, hoppy generates the Scala, Joern does the heavy lifting.

## Development

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest

# Lint and format
uv run ruff check .
uv run ruff format .

# Run tests with persistent Joern server (faster)
scripts/run_joern_server_tests.sh
```

## Limitations

- **First run setup**: Hoppy automatically downloads Joern on first run if not found in your PATH.
- **Performance**: CPG generation is resource-intensive. For large codebases, the initial parse can take minutes. Use `build_cpg()` / `load_cpg()` if you're running many queries on the same code.

## Contributing

Contributions welcome. Areas that need work:

- More language frontends (Go, Kotlin, C, C++, etc.)
- Better Python support
- More built-in rules
- Performance improvements
- Documentation and examples

See AGENTS.md for technical details on the codebase if you're working on it.

## Disclaimer
This project is mostly vibe-coded after initial manual implementation seed.
