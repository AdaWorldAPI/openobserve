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
