# db-hygiene-scanner

Automated database hygiene violation detection and AI-powered remediation for banking systems.

## Overview

db-hygiene-scanner detects and proposes fixes for five critical transaction and query management hygiene issues across multiple database platforms and programming languages.

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

### Scan a repository

```bash
db-hygiene-scanner scan /path/to/repo --output-file scan-results.json
```

### Generate fixes

```bash
db-hygiene-scanner fix /path/to/repo --output-file fixes.json
```

### Generate report

```bash
db-hygiene-scanner report scan-results.json --output-format html --output-file report.html
```

### Run full demo

```bash
db-hygiene-scanner demo --repo-path /app/src
```

## Supported Platforms

- Microsoft SQL Server (MSSQL)
- Oracle Database
- MongoDB
- EDB/Yugabyte (PostgreSQL-compatible)

## Supported Languages

- C# / .NET
- Java
- Python
- SQL

## Violation Types

1. **SELECT_STAR** - SELECT * queries (can hurt performance and expose sensitive columns)
2. **STRING_CONCAT_SQL** - SQL injection via string concatenation
3. **UNBATCHED_TXN** - Missing transaction batching (N+1 query problems)
4. **LONG_RUNNING_TXN** - Missing transaction timeouts
5. **READ_PREFERENCE** - Missing read preference configuration (MongoDB)

## License

MIT
