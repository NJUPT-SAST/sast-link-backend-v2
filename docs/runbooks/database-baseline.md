# Database V001 baseline

## Purpose

Register V001 for the pre-existing production schema without executing the V001 application DDL. The migration tool may create its own `schema_migrations` metadata table.

## Preconditions

Before baselining, obtain an approved maintenance window and a verified database backup. Set the production `DB_*` environment configuration, build the migration binary from the target release, and ensure no concurrent deployment is running. Quiesce every schema-changing job and DDL-capable administrative session for the entire baseline command; the catalog preflight and migration-version registration use separate database operations and cannot protect against an uncooperative concurrent DDL session.

## Preflight

First run `.\bin\migrate.exe version`. Then run the guarded baseline command below. The command checks the required V001 enum labels, table columns and defaults, constraints, indexes, trigger functions, and trigger definitions before registering the migration; an incompatible required object, dirty state, or a version other than 1 terminates without modifying application data. Extra database objects are allowed. This structured guard is not a substitute for reviewing the schema dump and backup before the maintenance window.

## Command

```powershell
.\bin\migrate.exe force 1 --confirm-existing-baseline
```

## Verification

Run:

```powershell
.\bin\migrate.exe version
```

It must print `version=1 dirty=false`. Query table counts before and after baselining and confirm that they are unchanged.

## Failure response

Stop. Do not run `force` with a different version. Restore from backup only under the database recovery procedure. Attach CLI error output to the incident or change record.

## Explicit prohibitions

- Do not run V001 `up` against this existing production database.
- Do not run down.
- Do not pass production credentials to tests.
- Do not use the local SQL dump as an input file.
