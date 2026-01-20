# LLM Agent Guide to hoppy

This document teaches LLM agents how to use the hoppy API to write security analysis queries. Work through these examples in order.

## Core Concepts

**hoppy** is a Python wrapper around Joern (a code property graph analysis tool). You write Python code, hoppy translates it to Scala, Joern executes it and returns results.

### The Three Key Abstractions

1. **Analyzer** - The session manager. Always use as a context manager (`with` statement).
2. **Pattern** - Matches code elements (calls, methods, parameters, etc.).
3. **Query** - Combines patterns to track data flows through code.

### Metavariables

Metavariables start with `$` and represent unknown values:

- `$IN` - User input (matches anything)
- `$X` - Any value (for unification)
- `$_` - Wildcard (doesn't enforce equality)

When the same metavariable appears in multiple places, hoppy enforces it has the same value at all locations. This is called **unification**.

## Essential Patterns

### Call - Function/Method Calls

```python
from hoppy import Call

# Match any call with this name
Call(name="execute")

# Match by full name (includes module/package)
Call(fullname="subprocess.run")

# Match with specific arguments
Call(name="execute", args=[Literal("SELECT * FROM users")])

# Match with dynamic argument (not a literal)
Call(name="execute", args=[Var("$SQL")])

# Match calls on a specific receiver type
Call(name="execute", receiver_type="Statement")

# Combine filters
Call(name="execute", receiver_type="Statement", args=[Var("$QUERY")])
```

### Parameter - Method Parameters

```python
from hoppy import Parameter

# Match any parameter
Parameter()

# Match by name
Parameter(name="userId")

# Match by annotation (framework-specific)
Parameter(annotation="RequestParam")

# Match with metavariable (binds the value)
Parameter(name="$IN")

# Combine conditions
Parameter(name="input", annotation="RequestBody")
```

### Method - Method Definitions

```python
from hoppy import Method

# Match by name
Method(name="login")

# Match by full name
Method(fullname="com.example.AuthController.login")

# Match by annotation
Method(annotation="PostMapping")

# Combine conditions
Method(name="login", annotation="PostMapping")
```

### Identifier - Variable References

```python
from hoppy import Identifier

# Match variable name
Identifier(name="user")

# Match with metavariable
Identifier(name="$VAR")
```

### Literal - Literal Values

```python
from hoppy import Literal

# Match specific string
Literal("SELECT")

# Match with metavariable (any literal)
Literal("$VAL")
```

### Var - Wildcard (Matches Anything)

```python
from hoppy import Var

# Match any expression, bind to metavariable
Var("$INPUT")

# Generic wildcard
Var("$_")
```

## Composition Patterns

### Or - Match Any Pattern

```python
from hoppy import Call, Or

# Match subprocess.run OR os.system
Or([
    Call(fullname="subprocess.run"),
    Call(fullname="os.system")
])

# Using | operator
Call(fullname="subprocess.run") | Call(fullname="os.system")
```

### And - Match All Patterns

```python
from hoppy import Call, And

# Match call named "execute" with first arg being dynamic
And([
    Call(name="execute"),
    Call(args=[Var("$QUERY")])
])

# Using & operator
Call(name="execute") & Call(args=[Var("$QUERY")])
```

### Not - Exclude Pattern

```python
from hoppy import Call, Not

# Match calls NOT named "sanitize"
Not(Call(name="sanitize"))

# Using ~ operator
~Call(name="sanitize")
```

### Inside - Match Within Context

```python
from hoppy import Call, Method, Inside

# Match calls inside a specific method
Call(name="execute").inside(Method(name="processUserInput"))

# Match calls inside methods with specific annotation
Call(name="execute").inside(Method(annotation="PostMapping"))
```

### DominatedBy - Control Flow Precedence

```python
from hoppy import Call, DominatedBy

# Match nodes preceded by an authentication check
Call(name="transfer").is_dominated_by(Call(name="isAuthenticated"))

# Match nodes NOT preceded by a check
Call(name="deleteUser").is_not_dominated_by(Call(name="checkPermission"))
```

### Field - Field Access

```python
from hoppy import Identifier, Field

# Match request.user.id
Identifier(name="request").field("user").field("id")

# Match user.is_authenticated
Identifier(name="user").field("is_authenticated")
```

## Building Queries

### Source-Only Queries

Find code elements without tracking data flow:

```python
from hoppy import Analyzer, Query, Call

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Find all subprocess.run calls
    q = Query.source(Call(fullname="subprocess.run"))
    results = analyzer.execute(q)

    for match in results:
        print(f"{match.file}:{match.line} - {match.code}")
```

### Simple Taint Flow

Track data from source to sink:

```python
from hoppy import Analyzer, Query, Call, Var

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Track from user input ($IN) to dangerous function
    q = Query.source(Var("$IN")).flows_to(Call(name="execute"))
    results = analyzer.execute(q)

    for match in results:
        print(f"{match.file}:{match.line}")
        if match.flow:
            for element in match.flow:
                print(f"  -> {element.file}:{element.line}: {element.code}")
```

### Multi-Step Flows

Track through multiple transformations:

```python
from hoppy import Analyzer, Query, Call

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Input -> parse -> validate -> execute
    q = (Query.source(Call(name="get_input"))
         .flows_to(Call(name="parse"))
         .flows_to(Call(name="validate"))
         .flows_to(Call(name="execute")))

    results = analyzer.execute(q)
```

### Using Sanitizers

Exclude flows that pass through safe functions:

```python
from hoppy import Analyzer, Query, Call, Var

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Find flows to execute that DON'T pass through sanitize/escape
    q = (Query.source(Var("$IN"))
         .flows_to(Call(name="execute"))
         .passes_not(Call(fullname=r".*(sanitize|escape|encode).*")))

    results = analyzer.execute(q)
```

### Using Auth Barriers

Check if operations are protected:

```python
from hoppy import Analyzer, Query, Call, rules

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Find dangerous operations NOT preceded by authentication
    q = Query.source(
        Call(name="deleteUser").is_not_dominated_by(rules.AuthBarrier())
    )

    results = analyzer.execute(q)
```

## Using Built-in Rules

hoppy includes pre-built patterns for common vulnerabilities. Use these instead of writing your own when possible.

### Cross-Language Rules

```python
from hoppy import Analyzer, Query, rules

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # SQL Injection
    q = Query.source(rules.WebSource()).flows_to(rules.SqlSink())
    results = analyzer.execute(q)

    # Command Injection
    q = Query.source(rules.WebSource()).flows_to(rules.CommandSink())

    # SSRF
    q = Query.source(rules.WebSource()).flows_to(rules.SsrfSink())

    # With sanitizers
    q = (Query.source(rules.WebSource())
         .flows_to(rules.SqlSink())
         .passes_not(rules.Sanitizer()))
```

### Language-Specific Rules

```python
from hoppy import Analyzer, Query, rules

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Python-specific rules
    q = Query.source(rules.python.WebSource()).flows_to(
        rules.python.CommandSink()
    )

    # Java-specific rules
    q = Query.source(rules.java.WebSource()).flows_to(
        rules.java.SqlSink()
    )

    # C#-specific rules
    q = Query.source(rules.csharp.WebSource()).flows_to(
        rules.csharp.XmlSink()
    )
```

### Available Rules by Language

#### Python (rules.python)
- `WebSource()` - FastAPI, Flask, Django request parameters
- `CommandSink()` - subprocess, os.system
- `SqlSink()` - execute(), raw()
- `PathTraversalSink()` - open(), os path operations
- `SsrfSink()` - requests.get, urllib
- `CodeInjectionSink()` - exec, eval
- `DeserializationSink()` - pickle.loads
- `TemplateInjectionSink()` - jinja2, flask templates
- `OpenRedirectSink()` - redirect functions
- `ArchiveExtractionSink()` - zipfile.extractall

#### Java (rules.java)
- `WebSource()` - Spring @RequestParam, @RequestBody, etc.
- `CommandSink()` - Runtime.exec, ProcessBuilder
- `SqlSink()` - Statement.execute, JdbcTemplate
- `SsrfSink()` - HttpClient, RestTemplate
- `XxeSink()` - DocumentBuilderFactory, SAXParser
- `DeserializationSink()` - ObjectInputStream
- `TemplateInjectionSink()` - Template.process
- `OpenRedirectSink()` - sendRedirect
- `InsecureCryptoSink()` - MD5, SHA1
- `ArchiveExtractionSink()` - ZipInputStream

#### Common (rules.common)
- `DynamicArg("$ANY")` - Matches non-literal arguments
- `Sanitizer()` - Common escape/sanitize/encode functions

## Real-World Vulnerability Patterns

### SQL Injection

```python
from hoppy import Analyzer, Query, rules

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # User input flows to SQL execution without sanitization
    q = (Query.source(rules.WebSource())
         .flows_to(rules.SqlSink())
         .passes_not(rules.Sanitizer()))

    results = analyzer.execute(q)

    for match in results:
        print(f"Potential SQL injection:")
        print(f"  File: {match.file}:{match.line}")
        print(f"  Code: {match.code}")

        # Show the full data flow path
        if match.flow:
            print(f"  Flow trace:")
            for element in match.flow:
                print(f"    -> {element.file}:{element.line}: {element.code}")
```

### Command Injection

```python
from hoppy import Analyzer, Query, rules, Call, Or

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Find user input flowing to command execution
    # Exclude flows that pass through any sanitization
    q = (Query.source(rules.WebSource())
         .flows_to(rules.CommandSink())
         .passes_not(rules.Sanitizer()))

    results = analyzer.execute(q)
```

### Authentication Bypass

```python
from hoppy import Analyzer, Query, rules, Call

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Find dangerous operations without authentication checks
    dangerous = Or([
        rules.CommandSink(),
        rules.SqlSink(),
        Call(name="transferMoney"),
        Call(name="deleteUser")
    ])

    q = Query.source(
        dangerous.is_not_dominated_by(rules.AuthBarrier())
    )

    results = analyzer.execute(q)

    for match in results:
        print(f"Unprotected dangerous operation:")
        print(f"  {match.file}:{match.line} - {match.code}")
```

### Path Traversal (Python)

```python
from hoppy import Analyzer, Query, rules

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/python_code")

    # User input flows to file operations
    # Exclude flows that pass through path normalization
    q = (Query.source(rules.python.WebSource())
         .flows_to(rules.python.PathTraversalSink())
         .passes_not(rules.python.PathTraversalSanitizer()))

    results = analyzer.execute(q)
```

### XXE (Java)

```python
from hoppy import Analyzer, Query, rules

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/java_code")

    # User-controlled XML parsed without secure configuration
    q = (Query.source(rules.java.WebSource())
         .flows_to(rules.java.XxeSink())
         .passes_not(rules.java.XxeSanitizer()))

    results = analyzer.execute(q)
```

### Insecure Deserialization

```python
from hoppy import Analyzer, Query, rules

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Python pickle
    q = Query.source(rules.WebSource()).flows_to(
        rules.python.DeserializationSink()
    )

    # Java serialization
    q = (Query.source(rules.java.WebSource())
         .flows_to(rules.java.DeserializationSink())
         .passes_not(rules.java.DeserializationSanitizer()))

    results = analyzer.execute(q)
```

## Working with Match Results

```python
from hoppy import Analyzer, Query, rules

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")
    q = Query.source(rules.WebSource()).flows_to(rules.SqlSink())
    results = analyzer.execute(q)

    for match in results:
        # Basic location info
        print(f"File: {match.file}")
        print(f"Line: {match.line}")
        print(f"Column: {match.column}")
        print(f"Code: {match.code}")

        # Method context
        print(f"Method: {match.method_name}")
        print(f"Class: {match.class_name}")
        print(f"Full signature: {match.method_fullname}")

        # What was actually called
        print(f"Called: {match.called_method}")

        # Metavariable bindings
        print(f"Bindings: {match.bindings}")
        # Example: {'$IN': 'userId', '$SQL': 'SELECT * FROM users WHERE id = ' + userId}

        # Full data flow trace (if available)
        if match.flow:
            print(f"Flow trace ({len(match.flow)} elements):")
            for i, element in enumerate(match.flow):
                print(f"  [{i}] {element.file}:{element.line}")
                print(f"      Code: {element.code}")
                print(f"      Method: {element.method}")
```

## Advanced Patterns

### Combining Multiple Sources

```python
from hoppy import Analyzer, Query, rules, Or

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # User input OR file system input
    source = Or([
        rules.WebSource(),
        Call(fullname=".*File.*read.*")
    ])

    q = Query.source(source).flows_to(rules.SqlSink())
    results = analyzer.execute(q)
```

### Combining Multiple Sinks

```python
from hoppy import Analyzer, Query, rules, Or

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Any dangerous sink
    dangerous = Or([
        rules.CommandSink(),
        rules.SqlSink(),
        rules.python.CodeInjectionSink()
    ])

    q = Query.source(rules.WebSource()).flows_to(dangerous)
    results = analyzer.execute(q)
```

### Context-Sensitive Queries

```python
from hoppy import Analyzer, Query, Call, Method, rules

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Only find SQL injection in controller methods
    q = (Query.source(rules.WebSource())
         .flows_to(rules.SqlSink())
         .inside(rules.Controller()))

    results = analyzer.execute(q)
```

### Custom Sink Patterns

```python
from hoppy import Analyzer, Query, Call, rules, common

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Custom sink: function that evaluates expressions
    dangerous_eval = Call(
        fullname=r".*(evaluate|evaluateExpression|compute).*",
        args=[common.DynamicArg("$EXPR")]  # Must be dynamic argument
    )

    q = Query.source(rules.WebSource()).flows_to(dangerous_eval)
    results = analyzer.execute(q)
```

### Multiple Sanitizers

```python
from hoppy import Analyzer, Query, rules, Or

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # Exclude flows passing through ANY of these sanitizers
    sanitizer = Or([
        rules.Sanitizer(),
        Call(name="validateInput"),
        Call(name="checkSafety")
    ])

    q = (Query.source(rules.WebSource())
         .flows_to(rules.CommandSink())
         .passes_not(sanitizer))

    results = analyzer.execute(q)
```

## Best Practices

1. **Use built-in rules when possible** - They're tested and cover framework-specific patterns.

2. **Start broad, then narrow** - Use `coverage="broad"` mode initially, then switch to `coverage="precision"` for fewer false positives.

3. **Examine flow traces** - Always inspect `match.flow` to understand if a finding is realistic or theoretical.

4. **Use sanitizers** - Most security rules need `.passes_not(rules.Sanitizer())` to avoid flagging properly sanitized code.

5. **Context matters** - Use `.inside(rules.Controller())` or `.is_dominated_by(rules.AuthBarrier())` to add context awareness.

6. **Check metavariables** - Look at `match.bindings` to see what values matched your metavariables.

7. **Performance** - Use `.summary()` on queries to disable flow traces for faster scanning when you only need locations.

8. **Language-specific** - Use `rules.python`, `rules.java`, or `rules.csharp` for language-optimized patterns.

## Common Mistakes

### Forgetting Context Manager

```python
# WRONG - Session never starts
analyzer = Analyzer()
analyzer.load_code("./src")
results = analyzer.execute(q)

# CORRECT
with Analyzer() as analyzer:
    analyzer.load_code("./src")
    results = analyzer.execute(q)
```

### Not Using Sanitizers

```python
# May flag properly sanitized code
q = Query.source(rules.WebSource()).flows_to(rules.SqlSink())

# Better - excludes sanitized flows
q = (Query.source(rules.WebSource())
     .flows_to(rules.SqlSink())
     .passes_not(rules.Sanitizer()))
```

### Incorrect Metavariable Usage

```python
# $X in both places must have SAME value
q = Query.source(Call(args=[Var("$X")])).flows_to(
    Call(args=[Var("$X")])
)
# This finds: dangerousFunc(userId) -> execute(userId)
# NOT: dangerousFunc(userId) -> execute(password)

# For independent values, use different metavariables
q = Query.source(Call(args=[Var("$IN")])).flows_to(
    Call(args=[Var("$OUT")])
)
```

### Missing Auth Context

```python
# Finds all delete operations (may be intended)
q = Query.source(Call(name="deleteUser"))

# Better - only finds unprotected deletes
q = Query.source(
    Call(name="deleteUser").is_not_dominated_by(rules.AuthBarrier())
)
```

## Discovery

Before writing complex queries, you should explore the codebase to find interesting methods and potential sinks.

```python
from hoppy import Analyzer

with Analyzer() as analyzer:
    analyzer.load_code("./path/to/code")

    # List all method definitions matching a pattern
    methods = analyzer.list_methods(".*login.*").unwrap()
    for m in methods:
        print(f"Found method: {m}")

    # List all unique function calls (to find sinks)
    calls = analyzer.list_calls(".*exec.*").unwrap()
    for c in calls:
        print(f"Found call: {c}")

    # Get a summary of external API calls (grouped by module)
    api_summary = analyzer.get_api_summary().unwrap()
    for module, methods in api_summary.items():
        print(f"Module {module} calls: {methods}")
```

## CLI Quick Reference

```bash
# Scan for vulnerabilities
hoppy scan ./path/to/code --lang python

# Output SARIF for CI/CD
hoppy scan ./src --sarif results.sarif

# Filter by severity
hoppy scan ./src --min-severity high

# Only map attack surface (no deep scans)
hoppy scan ./src --surface-only

# List methods and calls for discovery
hoppy list-methods ./src --calls --pattern "execute"
hoppy list-methods ./src --external

# Program slicing from custom sink
hoppy slice ./src --sink "execute.*query"

# List available slicing rules
hoppy slice --list-rules

# Use specific slicing rule
hoppy slice ./src --rule sql-injection
```

## Complete Example Script

```python
#!/usr/bin/env python3
"""
Security scan for Python web application using hoppy.
Finds common vulnerabilities: SQLi, Command Injection, Path Traversal, SSRF.
"""

from hoppy import Analyzer, Query, rules
from pathlib import Path

def scan_codebase(code_path: str):
    """Scan a Python codebase for security vulnerabilities."""

    with Analyzer() as analyzer:
        print(f"Loading code from {code_path}...")
        analyzer.load_code(code_path)

        vulnerabilities = []

        # 1. SQL Injection
        print("Scanning for SQL Injection...")
        q = (Query.source(rules.python.WebSource())
             .flows_to(rules.python.SqlSink())
             .passes_not(rules.Sanitizer()))

        results = analyzer.execute(q)
        for match in results:
            vulnerabilities.append({
                "type": "SQL Injection",
                "severity": "HIGH",
                "file": match.file,
                "line": match.line,
                "code": match.code,
                "flow": match.flow
            })

        # 2. Command Injection
        print("Scanning for Command Injection...")
        q = (Query.source(rules.python.WebSource())
             .flows_to(rules.python.CommandSink())
             .passes_not(rules.Sanitizer()))

        results = analyzer.execute(q)
        for match in results:
            vulnerabilities.append({
                "type": "Command Injection",
                "severity": "HIGH",
                "file": match.file,
                "line": match.line,
                "code": match.code,
                "flow": match.flow
            })

        # 3. Path Traversal
        print("Scanning for Path Traversal...")
        q = (Query.source(rules.python.WebSource())
             .flows_to(rules.python.PathTraversalSink())
             .passes_not(rules.python.PathTraversalSanitizer()))

        results = analyzer.execute(q)
        for match in results:
            vulnerabilities.append({
                "type": "Path Traversal",
                "severity": "HIGH",
                "file": match.file,
                "line": match.line,
                "code": match.code,
                "flow": match.flow
            })

        # 4. SSRF
        print("Scanning for SSRF...")
        q = (Query.source(rules.python.WebSource())
             .flows_to(rules.python.SsrfSink())
             .passes_not(rules.Sanitizer()))

        results = analyzer.execute(q)
        for match in results:
            vulnerabilities.append({
                "type": "SSRF",
                "severity": "HIGH",
                "file": match.file,
                "line": match.line,
                "code": match.code,
                "flow": match.flow
            })

        # 5. Code Injection (exec/eval)
        print("Scanning for Code Injection...")
        q = (Query.source(rules.python.WebSource())
             .flows_to(rules.python.CodeInjectionSink())
             .passes_not(rules.Sanitizer()))

        results = analyzer.execute(q)
        for match in results:
            vulnerabilities.append({
                "type": "Code Injection",
                "severity": "CRITICAL",
                "file": match.file,
                "line": match.line,
                "code": match.code,
                "flow": match.flow
            })

        return vulnerabilities


def print_results(vulnerabilities):
    """Pretty print vulnerability findings."""

    if not vulnerabilities:
        print("\nNo vulnerabilities found!")
        return

    print(f"\nFound {len(vulnerabilities)} potential vulnerabilities:\n")

    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"[{i}] {vuln['type']} - {vuln['severity']}")
        print(f"    File: {vuln['file']}:{vuln['line']}")
        print(f"    Code: {vuln['code']}")

        if vuln['flow']:
            print(f"    Data flow ({len(vuln['flow'])} steps):")
            for j, element in enumerate(vuln['flow']):
                print(f"      [{j+1}] {element.file}:{element.line}")
                if element.code:
                    print(f"          {element.code[:100]}...")
        print()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scan.py <path/to/code>")
        sys.exit(1)

    code_path = sys.argv[1]

    if not Path(code_path).exists():
        print(f"Error: Path '{code_path}' does not exist")
        sys.exit(1)

    vulnerabilities = scan_codebase(code_path)
    print_results(vulnerabilities)

    # Exit with error if vulnerabilities found
    sys.exit(1 if vulnerabilities else 0)
```

## Summary Checklist

When writing a security query with hoppy:

- [ ] Always use `with Analyzer() as analyzer:`
- [ ] Use `rules.WebSource()` for untrusted input
- [ ] Use language-specific rules (`rules.python`, `rules.java`)
- [ ] Add `.passes_not(rules.Sanitizer())` to exclude safe flows
- [ ] Consider auth context with `.is_dominated_by(rules.AuthBarrier())`
- [ ] Inspect `match.flow` to understand the data flow path
- [ ] Check `match.bindings` for metavariable values
- [ ] Use `coverage="precision"` for fewer false positives
- [ ] Use `.summary()` for better performance on large codebases

Now you know how to use hoppy to write security analysis queries. Start simple, iterate, and always validate your findings against the actual code.
