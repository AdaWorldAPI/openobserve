#!/usr/bin/env python3
"""Side-by-side parity probe for an OpenObserve HTTP endpoint.

capture: ingest a deterministic fixture into one instance, run a fixed query set,
         write the normalized answers as JSON.
diff:    compare two captures query by query.
Timestamps are stored relative to the fixture base, so two captures taken at
different times compare equal when the engine answers the same.
"""
import argparse, base64, datetime, json, sys, time, urllib.request

ORG = "default"


def call(base, auth, method, path, body=None):
    req = urllib.request.Request(base + path, method=method,
                                 data=None if body is None else json.dumps(body).encode())
    req.add_header("Authorization", "Basic " + auth)
    req.add_header("Content-Type", "application/json")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")


def fixture(base_us, mutate=False):
    """300 log rows and 3 metric series x 60 samples, all derived from the index."""
    logs = []
    for i in range(300):
        logs.append({
            "_timestamp": base_us + i * 1_000_000,
            "level": ["info", "warn", "error"][i % 3],
            "service": f"svc-{i % 5}",
            "status": [200, 200, 404, 500][i % 4],
            "latency_ms": (i * 37) % 251,
            "tenant": f"t{i % 2}",
            "message": f"request {i} handled path=/api/v{i % 3}/items",
        })
    if mutate:
        logs[7]["level"] = "error"
    metrics = []
    for s in range(3):
        for i in range(60):
            metrics.append({
                "__name__": "parity_requests_total", "__type__": "counter",
                "service": f"svc-{s}", "tenant": f"t{s % 2}",
                "_timestamp": base_us + i * 5_000_000,
                "value": float((s + 1) * i),
            })
            metrics.append({
                "__name__": "parity_queue_depth", "__type__": "gauge",
                "service": f"svc-{s}", "tenant": f"t{s % 2}",
                "_timestamp": base_us + i * 5_000_000,
                "value": float((i * (s + 3)) % 17),
            })
    return logs, metrics


SQL = {
    "count_all": "SELECT count(*) AS c FROM parity_logs",
    "count_by_level": "SELECT level, count(*) AS c FROM parity_logs GROUP BY level ORDER BY level",
    "sum_min_max": "SELECT sum(latency_ms) AS s, min(latency_ms) AS mn, max(latency_ms) AS mx FROM parity_logs",
    "filter_and_not": "SELECT count(*) AS c FROM parity_logs WHERE level = 'error' AND status <> 200 AND tenant = 't1'",
    "group_two_keys": "SELECT service, status, count(*) AS c FROM parity_logs GROUP BY service, status ORDER BY service, status",
    "distinct_service": "SELECT count(DISTINCT service) AS c FROM parity_logs",
    "avg_by_tenant": "SELECT tenant, avg(latency_ms) AS a FROM parity_logs GROUP BY tenant ORDER BY tenant",
    "histogram_1m": "SELECT histogram(_timestamp, '1 minute') AS t, count(*) AS c FROM parity_logs GROUP BY t ORDER BY t",
    "top_latency": "SELECT latency_ms, service FROM parity_logs ORDER BY latency_ms DESC, service LIMIT 5",
    "match_all": "SELECT count(*) AS c FROM parity_logs WHERE match_all('v2')",
    "like": "SELECT count(*) AS c FROM parity_logs WHERE message LIKE '%path=/api/v1/%'",
    "p95": "SELECT approx_percentile_cont(latency_ms, 0.95) AS p FROM parity_logs",
}

PROMQL_RANGE = {
    "raw_counter": "parity_requests_total",
    "rate_1m": "rate(parity_requests_total[1m])",
    "sum_by_tenant": "sum by (tenant) (parity_requests_total)",
    "max_gauge": "max(parity_queue_depth)",
    "avg_over_time": "avg_over_time(parity_queue_depth[1m])",
    "topk": "topk(1, parity_requests_total)",
    "increase": "increase(parity_requests_total[2m])",
    "count_series": "count(parity_queue_depth)",
}


def rel(v, base_us):
    """Rewrite absolute timestamps (us or RFC3339-less numbers) relative to the base."""
    if isinstance(v, dict):
        return {k: rel(x, base_us) for k, x in sorted(v.items())}
    if isinstance(v, list):
        return [rel(x, base_us) for x in v]
    if isinstance(v, int) and abs(v - base_us) < 3_600_000_000:
        return {"rel_us": v - base_us}
    if isinstance(v, float):
        return round(v, 6)
    if isinstance(v, str) and len(v) == 19 and v[10:11] == "T":
        try:
            t = datetime.datetime.fromisoformat(v).replace(tzinfo=datetime.timezone.utc)
            return {"rel_us": int(t.timestamp()) * 1_000_000 - base_us}
        except ValueError:
            return v
    return v


def capture(args):
    auth = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()
    base_us = (int(time.time()) // 60 * 60 - 900) * 1_000_000
    logs, metrics = fixture(base_us, args.mutate)
    out = {"endpoint_config": {}, "ingest": {}, "sql": {}, "promql": {}, "meta": {}}
    _, cfg = call(args.url, auth, "GET", "/config")
    out["endpoint_config"] = {k: cfg.get(k) for k in ("version", "commit_hash")} if isinstance(cfg, dict) else cfg
    st, r = call(args.url, auth, "POST", f"/api/{ORG}/parity_logs/_json", logs)
    out["ingest"]["logs"] = [st, r.get("status") if isinstance(r, dict) else r]
    st, r = call(args.url, auth, "POST", f"/api/{ORG}/ingest/metrics/_json", metrics)
    stat = r.get("status") if isinstance(r, dict) else r
    out["ingest"]["metrics"] = [st, sorted(stat, key=lambda x: x.get("name", "")) if isinstance(stat, list) else stat]
    start, end = base_us - 60_000_000, base_us + 600_000_000
    want = len(logs)
    for _ in range(60):
        _, r = call(args.url, auth, "POST", f"/api/{ORG}/_search",
                    {"query": {"sql": SQL["count_all"], "start_time": start, "end_time": end, "from": 0, "size": 10}})
        if isinstance(r, dict) and r.get("hits") and r["hits"][0].get("c") == want:
            break
        time.sleep(1)
    for name, sql in SQL.items():
        st, r = call(args.url, auth, "POST", f"/api/{ORG}/_search",
                     {"query": {"sql": sql, "start_time": start, "end_time": end, "from": 0, "size": 1000}})
        hits = r.get("hits") if isinstance(r, dict) else None
        out["sql"][name] = {"status": st, "hits": rel(hits, base_us) if hits is not None else rel(r, base_us)}
    s, e = base_us // 1_000_000, base_us // 1_000_000 + 300
    for name, q in PROMQL_RANGE.items():
        path = f"/api/{ORG}/prometheus/api/v1/query_range?query={urllib.request.quote(q)}&start={s}&end={e}&step=15"
        st, r = call(args.url, auth, "GET", path)
        res = r.get("data", {}).get("result") if isinstance(r, dict) else None
        norm = None
        if res is not None:
            norm = sorted(
                [{"metric": m.get("metric"),
                  "values": [[int(t) - s, round(float(v), 6)] for t, v in m.get("values", [])]} for m in res],
                key=lambda m: json.dumps(m["metric"], sort_keys=True))
        out["promql"][name] = {"status": st, "result": norm if norm is not None else r}
    _, r = call(args.url, auth, "GET", f"/api/{ORG}/streams/parity_logs/schema?type=logs")
    if isinstance(r, dict):
        out["meta"]["logs_schema"] = sorted((f.get("name"), f.get("type")) for f in r.get("schema", []))
    json.dump(out, open(args.out, "w"), indent=1, sort_keys=True)
    print(f"captured {len(SQL)} sql + {len(PROMQL_RANGE)} promql -> {args.out}")


def diff(args):
    a, b = json.load(open(args.a)), json.load(open(args.b))
    same = differ = 0
    for sec in ("ingest", "sql", "promql", "meta"):
        for k in sorted(set(a[sec]) | set(b[sec])):
            if a[sec].get(k) == b[sec].get(k):
                same += 1
            else:
                differ += 1
                print(f"DIFF {sec}.{k}\n  a: {json.dumps(a[sec].get(k))[:300]}\n  b: {json.dumps(b[sec].get(k))[:300]}")
    print(f"a={a['endpoint_config']} b={b['endpoint_config']}")
    print(f"same={same} differ={differ}")
    sys.exit(1 if differ else 0)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture")
    c.add_argument("--url", required=True); c.add_argument("--user", required=True)
    c.add_argument("--password", required=True); c.add_argument("--out", required=True)
    c.add_argument("--mutate", action="store_true", help="control: change one fixture row so diff must fire")
    c.set_defaults(fn=capture)
    d = sub.add_parser("diff"); d.add_argument("a"); d.add_argument("b"); d.set_defaults(fn=diff)
    a = p.parse_args(); a.fn(a)
