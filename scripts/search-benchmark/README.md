# Administrative user search benchmark

The query preserves case-insensitive literal substring search across account ID,
name, student ID, email, QQ, initials and profile fields. Phone searches remain
admin-only. V017 adds three PostgreSQL `pg_trgm` GIN indexes, keeping phone
separate. The repository searches each table independently and uses disjoint
`UNION ALL` branches, so count does not materialize a global distinct set. Each
page branch is bounded by `offset + limit` before combining results. Every filter
is applied inside the branches. One/two-character searches retain the original
scan because trigram indexes cannot selectively serve those patterns.

Two rejected alternatives were measured: indexing concatenated fields required
an extra exact recheck and made broad counts slower; unbounded `UNION DISTINCT`
materialized broad matches and made first-page retrieval much slower. Neither is
used in the final implementation.

Run only against a disposable local container, never an existing deployment:

```sh
docker run -d --name sast-search-perf -e POSTGRES_PASSWORD=benchmark \
  -e POSTGRES_DB=searchbench --cpus=1 --memory=1g postgres:16-alpine
# Wait for pg_isready, then apply the checked-out migration files to this
# container's searchbench database (psql -v ON_ERROR_STOP=1 for every file).
python3 scripts/search-benchmark/benchmark.py sast-search-perf /tmp/search-results
python3 scripts/search-benchmark/write_cost.py sast-search-perf /tmp/search-results
```

The script refuses container names outside `sast-search-perf*`, but it still
**truncates all users and dependent data inside that database**. It seeds 10,000
and 100,000 deterministic users, realistic email/student-ID/phone shapes, skewed
Chinese names, sparse profile URLs, and missing profiles. Five-thousand-row
transactions avoid exhausting the email uniqueness trigger's advisory locks.

Each shape compares the previous joined-OR query with the new independent
branches, verifies identical results, warms both twice, then records six samples
in alternating order using `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)`. Page queries
fetch the user row and department, matching the repository's join/pagination
work. `results.json` contains plans, all raw times and medians. Index sizes,
PostgreSQL settings and seed duration are also saved. These are warm-cache SQL
execution measurements, not end-to-end API throughput or production guarantees.
The write-cost script compares 1,000 contact/profile edits with and without the
indexes, rolling back every sample and index drop, and records execution time
and WAL bytes. The read baseline runs with the same indexes available, allowing the old planner to
use them if it can. No planner hints or disabled sequential scans are used.

V017 is still unmerged in this review, so the generator and both migration files
are changed together. Do not rewrite V017 in a database where it is already
applied. That deployment requires a separately numbered additive migration after
its actual latest schema version. Index creation and the existing generated
column rewrite require a planned write-maintenance window. `ANALYZE` populates
expression/initials statistics before the first ordered search. The down
migration removes only the indexes it owns and keeps the potentially shared
`pg_trgm` extension. Deployment needs permission to install that trusted
extension (or it must be preinstalled).

The later reviewed PR branches also contain the original V017. Sequential merge
resolution must preserve this branch's updated V017 and generator. Adding V020
here would be incorrect: deploying it before later V018/V019 would make a
version-based migration runner skip those migrations.
