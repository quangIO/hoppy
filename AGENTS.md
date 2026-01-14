# AGENTS.md

This document helps AI agents work effectively in the hoppy repository.

## Project Overview

**hoppy** is a grep-like tool for Joern CPGs (Code Property Graphs). It provides a Python DSL for writing code analysis queries that execute against Joern to find security vulnerabilities, code patterns, and data flows.

### Key Technologies
- **Python 3.12+** with uv package management
- **Joern** - Code property graph analysis tool
- **pytest** - Testing framework
- **ruff** - Linting and formatting

## Essential Commands

### Package Management
```bash
# Install dependencies
uv sync

# Add dependency
uv add <package>
```

### Testing
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_arguments.py

# Run with verbose output
pytest -v

# Run with pytest-sugar (colored output)
# (automatically enabled via dependencies)
```

### Faster Test Runs (Optional Joern Server)
```bash
# Start a shared Joern server once
joern --server --server-host 127.0.0.1 --server-port 8080 --nocolors

# Point tests at it (skips spawning a new Joern process)
HOPPY_JOERN_SERVER_URL=http://localhost:8080 pytest
```
Set `HOPPY_JOERN_SERVER_AUTOSTART=1` to have pytest start the server automatically, and
`HOPPY_JOERN_SERVER_PERSIST=1` to leave it running after tests.

Use the helper script to start/reuse the server and run tests:
```bash
scripts/run_joern_server_tests.sh
```

### Linting
```bash
# Check code style
ruff check .

# Format code
ruff format .

# Fix issues where possible
ruff check --fix .
```

## Code Organization

### Source Structure
```
src/hoppy/
├── __init__.py           # Main exports
├── analyzer.py           # High-level Analyzer interface
├── core/
│   ├── manager.py        # JoernSession - manages Joern process/server
│   └── match.py          # Match - represents query results
└── dsl/
    ├── patterns.py       # Pattern classes (Call, Literal, Identifier, etc.)
    └── query.py          # Query - builds source/flows_to queries
```

### Test Structure
```
tests/                    # pytest test files
test_app/                 # Python code samples for testing
vulnerable_apps/
  ├── vulnado/            # Java vulnerable application (Maven/Spring Boot)
  └── dvcsharp-api/       # C# vulnerable application (.NET Core)
workspace/                # Joern workspace (generated, in .gitignore)
```

## Key Classes and Patterns

### Analyzer (High-Level Interface)

**Entry point for code analysis:**
```python
from hoppy import Analyzer, Query, Call, Var, rules

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")
    # Using rules module is often easier than manual patterns
    q = Query.source(rules.WebSource()).flows_to(rules.SqlSink())
    results = analyzer.execute(q)
    for match in results:
        print(f"{match.file}:{match.line} - {match.code}")
```

**Key methods:**
- `load_code(path)` - Import Python code into Joern
- `build_cpg(src_path, out_path)` - Build CPG binary via joern-parse
- `load_cpg(path)` - Load pre-built CPG binary
- `execute(query)` - Run hoppy Query against loaded CPG
- `list_calls(pattern)` - List all function calls matching regex
- `list_methods(pattern)` - List all method definitions matching regex
- `raw_scala(scala)` - Execute raw Scala code directly

**Important:** Must be used as a context manager (`with Analyzer() as analyzer:`) to ensure proper Joern session cleanup.

### Query DSL

**Building queries:**
```python
# Source only (no taint tracking)
q = Query.source(Call(name="subprocess.call"))

# Simple flow using rules
q = Query.source(rules.WebSource()).flows_to(rules.CommandSink())

# Multi-step flow
q = (Query.source(Call(name="get_input"))
     .flows_to(Call(name="process"))
     .flows_to(Call(name="sink")))

# With sanitizers
q = (Query.source(rules.WebSource())
     .flows_to(rules.SqlSink())
     .passes_not(rules.Sanitizer()))
```

**Query methods:**
- `Query.source(pattern, arg_index=None)` - Define the source pattern
- `flows_to(pattern)` - Add taint flow step (chain multiple)
- `passes_not(pattern)` - Exclude flows passing through sanitizer
- `is_dominated_by(pattern)` - Filter for nodes preceded by pattern (e.g., Auth)
- `is_not_dominated_by(pattern)` - Filter for nodes NOT preceded by pattern

### Pattern Classes

**Core patterns in src/hoppy/dsl/patterns.py:**

- **Call** - Function calls
  - `Call(name="func")` - matches by name
  - `Call(fullname="module.func")` - matches by methodFullName
  - `Call(args=[Literal("value")])` - matches arguments
  - `Call(receiver_type="SomeType")` - matches receiver type

- **Literal** - Literal values
  - `Literal("value")` - matches literal value
  - `Literal("$X")` - metavariable (any value)

- **Identifier** - Variable names
  - `Identifier("var_name")` - matches variable name
  - `Identifier("$X")` - metavariable (any identifier)

- **Var** - Matches any expression (metavariable)
  - `Var("$X")` - binds to any value

- **Parameter** - Method parameters (often used for sources)
  - `Parameter(name="arg")` - matches parameter name
  - `Parameter(annotation="SomeAnnotation")` - matches annotation

- **Method** - Method definitions
  - `Method(name="func")` - matches method name
  - `Method(fullname="module.func")` - matches full name

- **Field** - Field access
  - `Field(receiver=Identifier("obj"), name="prop")` - matches `obj.prop`

**Composition patterns:**
- `And([p1, p2, ...])` (or `p1 & p2`) - All must match
- `Or([p1, p2, ...])` (or `p1 | p2`) - Any must match
- `Not(pattern)` (or `~pattern`) - Must not match
- `Inside(pattern)` - Must be inside context (e.g., Method)
- `DominatedBy(pattern)` - Must be preceded by pattern in CFG

**Pattern chaining:**
```python
pattern = Call(name="process").where(Method(name="dangerous"))
pattern = Call(name="read").inside(Method(name="handle"))
```

### Match Class

**Represents query results** from src/hoppy/core/match.py:
```python
match.file         # File path
match.line         # Line number
match.column       # Column number
match.code         # Code snippet
match.called_method # Method being called
match.method_fullname # Containing method
match.bindings     # Dict of metavariable values (e.g., {"$X": "value"})
match.class_name   # Simple class name of containing method
match.method_name  # Simple method name of containing method
```

### JoernSession (Low-Level)

**Manages Joern process/server communication** in src/hoppy/core/manager.py:
- Starts Joern process or connects to server
- Handles command sending and output parsing
- Thread-safe with locking
- Auto-cleanup on context exit

**Key methods:**
- `send_command(cmd)` - Send raw command, return output
- `run_scala(scala)` - Execute Scala code
- `run_query(query, format="json")` - Run Query, parse JSON
- `import_code(path)` - Import code into Joern
- `load_cpg(path)` - Load CPG binary
- `save_cpg(path)` - Save CPG to binary

## Testing Patterns

### Standard Test Structure
```python
import sys
import os
import unittest
sys.path.insert(0, os.path.abspath("src"))

from hoppy import Analyzer, Query, Call, Var

class TestFeature(unittest.TestCase):
    def test_something(self):
        with Analyzer() as analyzer:
            analyzer.load_code("./test_app/sample.py")
            q = Query.source(Call(name="target"))
            results = analyzer.execute(q)

            self.assertEqual(len(results), expected_count)
            self.assertEqual(results[0].line, expected_line)
```

### Test Files in tests/
- `test_arguments.py` - Argument matching
- `test_cfg.py` - Control flow graph patterns
- `test_composition.py` - Multi-step flows and unification
- `test_context.py` - Method context patterns
- `test_edge_cases.py` - Edge cases and error handling
- `test_metavars.py` - Metavariable handling
- `test_persistence.py` - CPG save/load
- `test_real_world.py` - Real-world vulnerability patterns
- `test_sanitizers.py` - Sanitizer patterns
- `test_snippets.py` - Code snippets
- `test_types.py` - Type-based matching

### Test Code in test_app/
Small Python files used for testing:
- `main.py` - Basic test code
- `webapp.py` - Vulnerable Flask application
- `auth.py`, `composition.py`, `context.py`, etc. - Pattern-specific test cases

## Important Gotchas

### Metavariable Handling
1. **Metavariables start with `$`**: `$X`, `$IN`, `$USER`, etc.
2. **Global unification**: Same `$X` in source and sink must have same value
3. **Wildcards**: `$_` is a generic wildcard that doesn't enforce equality
4. **Var()** matches any expression but **Parameter()** is needed for untrusted inputs

### Query Generation
1. Joern's Python frontend uses `methodFullName` format: `filename.py:<module>.func`
2. Use regex in `fullname=` for flexible matching: `"subprocess.*call"`
3. Source patterns using `Var()` are forced to `cpg.parameter` (untrusted input only)

### Context Manager Required
Analyzer **must** be used as context manager:
```python
# ❌ Wrong - Joern process won't start
analyzer = Analyzer()
analyzer.load_code("...")
results = analyzer.execute(q)

# ✅ Correct
with Analyzer() as analyzer:
    analyzer.load_code("...")
    results = analyzer.execute(q)
```

### CPG Persistence
```python
# Build once
analyzer_builder = Analyzer()
analyzer_builder.build_cpg("./src", "cpg.bin")

# Load multiple times for faster testing
with Analyzer() as analyzer:
    analyzer.load_cpg("cpg.bin")
    results = analyzer.execute(q)
```

### File Paths
- Always use absolute paths for CPG operations
- Joern stores workspace in `workspace/` directory (in .gitignore)
- File paths in Match objects are inferred from `methodFullName`

### Or Patterns with Metavars
When using `Or([pattern1, pattern2])` with metavariables, binding extraction handles each branch separately with if-else logic.

### Sanitizers
`.passes_not(pattern)` filters flows where ANY element matches the sanitizer pattern. Used to exclude safe flows.

## Rules Module

**Standardized security patterns in src/hoppy/rules/:**
The `rules` module provides predefined sources, sinks, and discovery patterns for **Java, C#, and Python**.

```python
from hoppy import rules

# Cross-language generic patterns (Or-composition of all languages)
source = rules.WebSource()
sql_sink = rules.SqlSink()
cmd_sink = rules.CommandSink()
ssrf_sink = rules.SsrfSink()

# Language-specific patterns
java_sql = rules.java.SqlSink()
csharp_xml = rules.csharp.XmlSink()
python_traversal = rules.python.PathTraversalSink()

# Discovery rules
controllers = rules.Controller()
auth_barrier = rules.AuthBarrier()
```

### Key Rules
- `WebSource("$IN")` - Matches untrusted web inputs (Spring, ASP.NET, FastAPI/Flask).
- `Controller()` - Matches methods that act as web endpoints.
- `AuthBarrier()` - Matches methods or attributes representing authentication checks.
- `Sanitizer()` - Matches common sanitization function names (escape, sanitize, etc.).
- `DynamicArg("$X")` - Matches an argument that is NOT a literal (likely tainted).

### Sinks available:
- `SqlSink()`
- `CommandSink()`
- `SsrfSink()`
- `XmlSink()` (C#)
- `PathTraversalSink()` (Python)
- `CodeInjectionSink()` (Python)
- `DeserializationSink()` (Python)

### ScanRules
Pre-configured vulnerability detection rules:
```python
from hoppy.rules import get_scan_rules
rules = get_scan_rules(language="java")
for rule in rules:
    print(f"Running {rule.name}...")
    results = analyzer.execute(rule.query)
```
## Structural Metadata Extraction

Avoid brittle string parsing of `method_fullname`. Use the structural properties provided by the `Match` object:

```python
# Returns the simple method name (e.g., "Login" instead of full signature)
action = match.method_name

# Returns the simple class name (e.g., "AccountController")
controller = match.class_name
```
These properties are derived from the CPG's node hierarchy (`definingTypeDecl` and `astParentFullName`), ensuring accuracy across different language frontends (Java, C#, etc.).

## Joern/Scala Technical Learnings

1.  **Type-Safe JSON Serialization**: Joern's JSON exporter has issues with inferred `Any` types in tuples. 
    *   **Pitfall**: `Option[Int].getOrElse("")` results in `Any` (mixing `Int` and `String`).
    *   **Fix**: Explicitly convert to string first: `Option[Int].map(_.toString).getOrElse("")`.
2.  **Node-Aware Properties**: 
    *   `Method` nodes and `CfgNode` (Call, Identifier) nodes have different property structures.
    *   When searching for `Method` definitions, use `io.shiftleft.codepropertygraph.generated.nodes.Method` type checks in Scala to safely access `fullName` and `astParentFullName`.
3.  **Flow Result Mapping**: 
    *   Flow results return a `Path` object. The "sink" is always the last element: `f.elements.last`.
    *   To get the containing method of a sink, use `target.start.method.fullName.l.headOption`.

## Code Conventions

### Style
- Use type hints where appropriate (project uses `typing` module)
- Use dataclasses for pattern classes (all in `patterns.py`)
- Follow PEP 8 (enforced by ruff)

### Import Patterns
```python
from hoppy import Analyzer, Query, Call, Literal, Identifier, Var
from hoppy import Method, Field, And, Or, Not, Inside, DominatedBy
```

### Naming
- Classes: PascalCase (Analyzer, Query, Pattern)
- Methods: snake_case (load_code, execute_query)
- Constants: UPPER_CASE (not common)
- Metavariables: $UPPER_SNAKE_CASE ($IN, $USER, $X)

## External Dependencies

### Joern
- **Required**: Joern binary must be installed and in PATH
- Process starts with `joern --nocolors --nobanner` for easier parsing
- Server mode available: `Analyzer(use_server=True, server_url="http://localhost:8080")`
- Joern workspace generated in `workspace/` directory

### Python Dependencies (from pyproject.toml)
- `requests>=2.32.5` - HTTP requests for server mode
- `pytest>=9.0.2` - Testing
- `pytest-sugar>=1.1.1` - Test output formatting
- `pytest-xdist>=3.8.0` - Parallel test execution
- `ruff>=0.14.10` - Linting and formatting

## Vulnerability Patterns

Real-world examples in `tests/test_real_world.py`:

### SQL Injection
```python
q = (Query.source(Var("$IN"))
     .flows_to(Call(name="execute"))
     .passes_not(Call(fullname="sanitize|escape|encode")))
```

### Command Injection
```python
sinks = Call(fullname="system|run|popen|spawn|call")
q = Query.source(Var("$IN")).flows_to(sinks)
```

### Path Traversal
```python
q = (Query.source(Var("$IN"))
     .flows_to(Call(name="open"))
     .passes_not(Call(fullname="basename|abspath|realpath")))
```

## Senior Debugging Principles

When working with Joern and the Hoppy DSL, follow these principles to avoid "blind guessing" and brittle fixes:

### 1. The "Ground Truth" Principle
**Don't guess the graph; ask it.** If a Python pattern isn't matching, use `analyzer.raw_scala()` to inspect the raw CPG nodes.
*   **Action**: Run `cpg.method.name(".*target.*").l` to see the exact `fullName`, `signature`, and `astParent` properties.
*   **Reason**: Language frontends (Java, C#, Python) have different naming conventions. Seeing the raw data reveals the true structure.

### 2. Graph over Strings
**Prefer graph traversals over regex.** String-parsing a `methodFullName` is brittle; traversing the graph is language-agnostic.
*   **Action**: Instead of `fullname.split(".")`, use `node.astParentFullName` or `node.definingTypeDecl.name`.
*   **Reason**: Joern is a graph database. Leveraging the AST and Type hierarchy is inherently more robust than text manipulation.

### 3. Boundary Isolation
**Isolate the script from the wrapper.** If the Analyzer fails, separate the generated Scala from the Python execution logic.
*   **Action**: Extract the Scala code via `query.generate_scala()` and run it directly in a standalone `joern` shell.
*   **Reason**: Complex failures (like `ClassCastException`) often happen at the boundary where Scala types are serialized to JSON for Python. Isolating the script reveals type inference issues.

### 4. Validation as a Signal
**Trust the schema.** Pydantic `ValidationError` messages are not just noise; they indicate a broken contract.
*   **Action**: If a schema fails after a "fix," check the tuple indices and types in both `ScalaCompiler` and `Match.from_json`.
*   **Reason**: The schema ensures that the compiler's output and the parser's expectations remain perfectly aligned.

### 5. Explicit over Implicit
**Predictability beats "magic."** Avoid APIs that hide logic behind implicit assumptions.
*   **Action**: Patterns like `Call(fullname="...")` use exact regex matching. If you need a partial match, use explicit wildcards like `".*target.*"`.
*   **Reason**: Explicit patterns are easier to debug and prevent "magic" behavior that surprises the user when signatures change.

## Debugging

### Print Generated Scala
```python
q = Query.source(Call(name="target"))
print(f"Scala: {q.generate_scala()}")
results = analyzer.execute(q)
```

### Inspect Matches
```python
for r in results:
    print(f"{r.file}:{r.line} - {r.code}")
    print(f