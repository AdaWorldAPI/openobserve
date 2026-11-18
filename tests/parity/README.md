# Parity probe against an OpenObserve HTTP endpoint

`o2_parity.py capture` ingests a fixed fixture (300 log rows, 2 metrics × 3 series × 60 samples) into
one instance, runs 12 SQL and 8 PromQL range queries and writes the normalised answers. `diff`
compares two captures. Timestamps are stored relative to the fixture base, so captures taken at
different times compare. Each capture needs a fresh data directory: a second ingest doubles the rows.

```bash
python3 tests/parity/o2_parity.py capture --url http://127.0.0.1:5080 --user <root email> --password <root password> --out fork.json
```

```bash
python3 tests/parity/o2_parity.py diff tests/parity/upstream-v1.1.2.json fork.json
```

`upstream-v1.1.2.json` is the capture from the published `openobserve-v1.1.2-linux-amd64` binary
(commit `d16d693`), taken 2026-11-17. `control.sh <binary> <work dir>` runs the two controls: the same
binary twice must agree (measured: 23 same, 0 differ) and a mutated fixture row must differ
(measured: 2 differ, `count_by_level` and `filter_and_not`).

## Enterprise edition as a second oracle

The published enterprise binary (`openobserve-ee-v1.1.2-linux-amd64`, same commit `d16d693`) was run
next to the open-source one on 2026-11-18, both in local mode with no licence key.

- **Shared surface:** the capture above is identical on both editions (23 same, 0 differ).
- **Routes:** `o2_ee_surface.py` probes every parameter-free GET route of the fork's router on two
  instances and records where the status differs. `enterprise-v1.1.2-surface.json` holds the 50 routes
  that differ, with the status on each side and the top-level keys of the enterprise answer, never a
  body. Controls: the open-source binary against itself gives 0, and an unreachable instance ends
  the run with an error. A route that holds the connection open is recorded as `timeout`.
- **Log patterns:** `enterprise-v1.1.2-log-patterns.json` is what
  `POST /api/default/streams/parity_logs/patterns/extract` returned for the fixture. Templates and
  frequencies were the same in three runs; timings were not, so they are left out. It analysed 100
  of the 300 rows.

- **Log pattern rules:** `o2_patterns.py` ingests five message shapes with fixed counts (120, 80,
  60, 34, 6) and 14 one-rule probes, each into a fresh stream, and asks for patterns over the exact
  ingest window with `size` 5000. Then the answer covers every row: three captures were
  byte-identical. With the default window and size the binary samples and the row count changes from
  run to run (the capture above saw 100 of 300). `enterprise-v1.1.2-pattern-shapes.json` is that
  capture. Left out because they are not stable: timings, `z_score` (last digit), and the order of
  patterns with equal frequency. Controls: one shape alone gives one template; the 6-row shape gives
  none.
- **Fork side:** `src/log_patterns` answers the same messages and is tested against that file. It
  matches the five shapes, both controls and 9 of the 14 probes. The 5 it does not match yet are
  named in `src/log_patterns/tests/oracle.rs`: runs of adjacent variable tokens, and the kinds
  `<:UUID>`, `<:TIMESTAMP>`, `<:IDENTIFIERS>`. It is not wired to the route yet.

```bash
python3 tests/parity/o2_patterns.py --url http://127.0.0.1:5091 --user <root email> --password <root password> --out shapes.json
```

```bash
python3 tests/parity/o2_ee_surface.py --router src/api/http/src/handler/http/router/mod.rs --a http://127.0.0.1:5081 --b http://127.0.0.1:5091 --user <root email> --password <root password> --out surface.json
```

What each advertised enterprise feature did on that run:

| Feature | Open source | Enterprise | State |
|---|---|---|---|
| Log patterns | 404 | 200, patterns returned | exercised on the fixture |
| Query management | 404 | `query_manager/status` 200 | answers, empty |
| Sensitive data redaction | 404 | `re_patterns`, `re_patterns/built-in` 200 | answers; no pattern applied |
| Anomaly detection | 404 | `anomaly_detection` 200 | answers, empty |
| Incidents | `incidents/stats` 403 | 200 | answers, empty; needs firing alerts |
| Service graph | 404 | `service_graph/topology/current` 200 | answers, empty; needs traces |
| Correlation | 404 | `service_streams` 200 | answers, empty |
| AI assistant | 404 | `ai/toolsets` 200 | answers, empty; needs an AI key |
| RBAC | `roles`, `groups` 403 | 500 "OpenFGA store not initialized yet" | needs OpenFGA |
| Rate limiting | 404 | `ratelimit/*` 400, org has no access | meta organisation only |
| SSO | `sso_enabled` false | `sso_enabled` false | needs Dex; not exercised |
| SRE agent | — | service account created at start | needs the external agent; not exercised |
| Audit trail | — | — | off by default; not exercised |
| Pipeline remote destinations | — | — | not exercised |
| Metrics downsampling | — | — | set by environment; not exercised |
| Federated search | — | — | needs several clusters; not exercised |
