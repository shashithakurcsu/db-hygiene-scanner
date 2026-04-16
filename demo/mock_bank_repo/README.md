# Mock Banking Repository

This repository contains intentionally flawed database access code for testing the DB Hygiene Scanner tool. It simulates a typical banking application with services for payments, accounts, and data migration.

## Purpose

The code in this repository is **NOT production code**. Every file except `ddl_scripts.sql` contains deliberate database hygiene violations that the scanner is expected to detect. The violations span multiple database platforms, languages, and severity levels.

## Structure

```
src/
  python/
    payment_service.py   - psycopg2 (EDB/Yugabyte) payment processing
    account_query.py     - SQLAlchemy (Oracle) account lookups
    mongo_operations.py  - pymongo (MongoDB) account operations
  sql/
    stored_procedures.sql - MSSQL stored procedures
    ddl_scripts.sql       - Clean DDL (no violations - false positive test)
    migration_scripts.sql - Oracle PL/SQL migration procedures
```

## Violation Categories

| Category | Count | Severity Range |
|----------|-------|----------------|
| SELECT_STAR | 10 | MEDIUM |
| SQL_INJECTION | 4 | CRITICAL |
| NO_TIMEOUT | 4 | HIGH |
| NO_READ_PREFERENCE | 4 | HIGH |
| UNBATCHED_UPDATES | 2 | HIGH |
| UNBATCHED_INSERT | 1 | HIGH |
| NO_PROJECTION | 1 | MEDIUM |
| NO_BULK_WRITE | 1 | HIGH |
| MISSING_TRY_CATCH | 1 | HIGH |
| NO_FAST_FORWARD_CURSOR | 1 | MEDIUM |
| CURSOR_LOOP_UPDATE | 1 | HIGH |
| COMMIT_IN_LOOP | 1 | MEDIUM |
| DYNAMIC_SQL_WITHOUT_BIND_VARIABLES | 1 | HIGH |

**Total: 30 intentional violations across 5 files, covering 4 database platforms.**

## Database Platforms Covered

- **EDB/Yugabyte (PostgreSQL)** - via psycopg2
- **Oracle** - via SQLAlchemy and PL/SQL
- **MongoDB** - via pymongo
- **MSSQL** - via T-SQL stored procedures

## False Positive Testing

`ddl_scripts.sql` contains clean DDL statements (CREATE TABLE, CREATE INDEX, FOREIGN KEY). The scanner should produce zero findings for this file.

## Manifest

See `VIOLATIONS_MANIFEST.json` for the complete catalog of all 30 violations with line ranges, code snippets, severity levels, and banking context descriptions.
