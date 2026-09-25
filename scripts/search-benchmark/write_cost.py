#!/usr/bin/env python3
"""Measure transactional update cost with/without the search indexes.
Run after benchmark.py against the same disposable container. Each measurement
rolls back both its index drops and 1,000 contact/profile edits. No rows persist.
"""
import json
import pathlib
import statistics
import subprocess
import sys

container, output = sys.argv[1:]
if not container.startswith('sast-search-perf'):
    raise SystemExit('refusing non-benchmark container')
out = pathlib.Path(output)
out.mkdir(parents=True, exist_ok=True)
results = {}
for shape, update in {
    'contact': 'UPDATE "user" SET qq_number = qq_number || \'x\' WHERE id <= 1000',
    'profile': "UPDATE profile SET nickname = nickname || 'x' WHERE user_id <= 1000",
}.items():
    plans = {'before': [], 'after': []}
    for iteration in range(8):
        for name in (('before', 'after') if iteration % 2 == 0 else ('after', 'before')):
            drop = '' if name == 'after' else (
                'DROP INDEX idx_user_search; DROP INDEX idx_profile_search; '
                'DROP INDEX idx_user_phone_search;')
            raw = subprocess.check_output(['docker', 'exec', '-i', container,
                'psql', '-XqAt', '-U', 'postgres', '-d', 'searchbench', '-v', 'ON_ERROR_STOP=1'],
                input=('BEGIN; ' + drop + 'EXPLAIN (ANALYZE, BUFFERS, WAL, FORMAT JSON) '
                       + update + '; ROLLBACK;').encode()).decode().strip()
            plan = json.loads(raw)[0]
            if iteration >= 2:
                plans[name].append(plan)
    results[shape] = dict(plans=plans,
        median_ms={k: statistics.median(p['Execution Time'] for p in v) for k,v in plans.items()},
        median_wal_bytes={k: statistics.median(p['Plan']['WAL Bytes'] for p in v) for k,v in plans.items()})
    (out/'write-cost.json').write_text(json.dumps(results, indent=2))
    print(shape, results[shape]['median_ms'], flush=True)
