#!/usr/bin/env python3
"""Deterministic local PostgreSQL search benchmark; never targets a host database.
Usage: python3 scripts/search-benchmark/benchmark.py CONTAINER OUTPUT_DIRECTORY
Requires an isolated PostgreSQL 16 container with migrations applied. Destructively
replaces users in the container's searchbench database. Container names must start
with sast-search-perf. Uses psql inside Docker, with no Python dependencies.
"""
import json
import pathlib
import statistics
import subprocess
import sys
import time

container, output = sys.argv[1:]
if not container.startswith('sast-search-perf'):
    raise SystemExit('refusing non-benchmark container')
out = pathlib.Path(output)
out.mkdir(parents=True, exist_ok=True)

def sql(statement):
    return subprocess.check_output(['docker', 'exec', '-i', container, 'psql',
        '-XAt', '-U', 'postgres', '-d', 'searchbench', '-v', 'ON_ERROR_STOP=1'],
        input=statement.encode()).decode().strip()

columns = ['"user".id::text', '"user".name', '"user".student_id',
    '"user".login_email', '"user".qq_number', 'profile.nickname',
    'profile.blog_url', 'profile.github_url', '"user".name_initials']
results = []
for size in (10000, 100000):
    sql('TRUNCATE "user" RESTART IDENTITY CASCADE;')
    seed_start = time.monotonic()
    for start in range(1, size + 1, 5000):
      sql(f'''INSERT INTO "user" (name,phone_number,qq_number,password,student_id,email_type,login_email)
      SELECT CASE WHEN n % 997 = 0 THEN '刘华强' WHEN n % 331 = 0 THEN '张三' ELSE '王小明' END,
      '139'||lpad(n::text,8,'0'),(900000000+n)::text,'benchmark-hash',
      'B'||lpad(n::text,8,'0'),'njupt_email','member'||n||'@njupt.edu.cn'
      FROM generate_series({start},{min(start+4999,size)}) n;''')
    sql(f'''
      INSERT INTO profile (user_id,nickname,blog_url,github_url)
      SELECT id,'member-'||id,CASE WHEN id % 1021 = 0 THEN 'https://rareblog.example/'||id ELSE NULL END,
      CASE WHEN id % 17 = 0 THEN 'https://github.com/member-'||id ELSE NULL END
      FROM "user" WHERE id % 29 <> 0;
      VACUUM ANALYZE "user"; VACUUM ANALYZE profile;''')
    (out/f'seed-{size}.txt').write_text(str(time.monotonic()-seed_start))
    for keyword, phone in [('lhq', False), ('zs', False), ('张', False),
            ('rareblog', False), ('not-found-person', False), ('12345', False),
            ('13900012345', True), ('njupt', False), ('%_', False)]:
        pattern = '%' + keyword.replace('\\','\\\\').replace('%','\\%').replace('_','\\_') + '%'
        quoted = "'" + pattern.replace("'", "''") + "'"
        cols = columns + (['"user".phone_number'] if phone else [])
        predicate = '(' + ' OR '.join(c + ' ILIKE ' + quoted + " ESCAPE '\\'" for c in cols) + ')'
        user_predicate = '(' + ' OR '.join(c + ' ILIKE ' + quoted for c in columns if not c.startswith('profile.')) + ')'
        candidate = 'SELECT id FROM "user" WHERE ' + user_predicate
        profile_predicate = '(' + ' OR '.join(c + ' ILIKE ' + quoted for c in columns if c.startswith('profile.')) + ')'
        candidate += ' UNION ALL SELECT "user".id FROM "user" JOIN profile ON profile.user_id="user".id WHERE ' + profile_predicate + ' AND NOT COALESCE(' + user_predicate + ',false)'

        if phone:
            candidate += ' UNION ALL SELECT "user".id FROM "user" LEFT JOIN profile ON profile.user_id="user".id WHERE phone_number ILIKE ' + quoted + ' AND NOT COALESCE(' + user_predicate + ' OR ' + profile_predicate + ',false)'
        base = ' FROM "user" LEFT JOIN profile ON profile.user_id="user".id WHERE ' + predicate
        after = ' FROM "user" LEFT JOIN profile ON profile.user_id="user".id WHERE "user".id IN (' + candidate + ')' if len(keyword) >= 3 else base
        for shape in ('count', 'page'):
            prefix = 'SELECT count(*)' if shape == 'count' else 'SELECT "user".*,profile.department'
            suffix = '' if shape == 'count' else ' ORDER BY "user".id LIMIT 20'
            branches = candidate.split(' UNION ALL ')
            if shape == 'page':
                branches = ['(' + q + ' ORDER BY 1 LIMIT 20)' for q in branches]
            matched = ' UNION ALL '.join(branches)
            optimized = 'SELECT count(*) FROM (' + matched + ') AS matches' if shape == 'count' else 'SELECT "user".*,profile.department FROM "user" LEFT JOIN profile ON profile.user_id="user".id WHERE "user".id IN (' + matched + ') ORDER BY "user".id LIMIT 20'
            queries = {'before':prefix+base+suffix, 'after':optimized if len(keyword) >= 3 else prefix+base+suffix}
            values = {name: sql(q) for name,q in queries.items()}
            assert values['before'] == values['after'], (keyword, values)
            timings = {name:[] for name in queries}
            plans = {}
            for iteration in range(8):
                for name in (('before','after') if iteration % 2 == 0 else ('after','before')):
                    plan = json.loads(sql('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) '+queries[name]))[0]
                    if iteration >= 2:
                        timings[name].append(plan['Execution Time'])
                    plans[name] = plan
            row = dict(size=size,keyword=keyword,phone=phone,shape=shape,
                result=values['before'], milliseconds=timings,
                median_ms={k:statistics.median(v) for k,v in timings.items()},plans=plans)
            results.append(row)
            (out/'results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2))
            print(size,keyword,shape,row['median_ms'],flush=True)
    (out/f'storage-{size}.txt').write_text(sql("SELECT relname,pg_size_pretty(pg_relation_size(oid)) FROM pg_class WHERE relname LIKE '%search%' ORDER BY relname"))
(out/'environment.txt').write_text(sql('SELECT version(); SHOW shared_buffers; SHOW work_mem; SHOW max_parallel_workers_per_gather;'))
