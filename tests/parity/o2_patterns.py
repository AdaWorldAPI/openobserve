#!/usr/bin/env python3
"""Log pattern oracle: five message shapes with fixed counts, extracted over the exact ingest window."""
import argparse, base64, json, sys, time

from o2_parity import ORG, call

# (count, shape). The capture stores the messages, so `src/log_patterns/tests/oracle.rs` reads them.
SHAPES = [
    (120, lambda i: f"request {i} handled path=/api/v{i % 3}/items"),
    (80, lambda i: f"user u{i % 7} logged in from 10.0.{i % 4}.{i % 250}"),
    (60, lambda i: f"cache miss for key k{i} after {i % 90} ms"),
    (34, lambda i: f"connection to db-{i % 2} timed out"),
    (6, lambda i: f"disk /dev/sd{'abc'[i % 3]} is {80 + i}% full"),
]
# One-shape windows: the first keeps its template, the second is under the minimum cluster size.
CONTROLS = {"one_shape": "cache miss%", "below_minimum": "disk %"}
NAMES = "alice bob carol dave erin frank grace heidi ivan judy karl liam mona nina oscar peggy quinn ruth sam tina".split()
# One rule per probe; each goes to its own stream.
PROBES = {
    "first_word": [f"{w} started job {i} ok" for w in ("alpha", "beta") for i in range(20)],
    "fifth_word": [f"job {i} finished with {w}" for w in ("success", "failure") for i in range(20)],
    "sixth_word": [f"one two three four five {w} six seven" for w in ("red", "blue") for _ in range(20)],
    "seventh_word": [f"one two three four five six {w} seven" for w in ("red", "blue") for _ in range(20)],
    "constant_number": ["connected to port 8080 ok"] * 20,
    "leading_number": [f"{i} items synced to store" for i in range(30)],
    "short_rows": [f"user {n} logged out" for n in NAMES] * 2,
    "extra_spaces": [f"alpha {sp}beta gamma delta x{i}" for sp in ("", " ") for i in range(12)],
    "ipv4_and_number": [f"peer 10.0.0.{i} asked {i} times" for i in range(20)],
    "ipv4_next_to_number": [f"from 10.0.0.{i} {i} bytes" for i in range(20)],
    "adjacent_numbers": [f"sum of {i} {i + 1} is ready now" for i in range(20)],
    "adjacent_mixed": [f"pair a{i} b{i} is ready now ok" for i in range(20)],
    "word_then_number": [f"one two three four five six seven {w} {i}" for w in ("red", "blue") for i in range(20)],
    "other_kinds": [f"mail a{i}@example.com id 123e4567-e89b-12d3-a456-4266141740{i:02d} "
                    f"at 2026-11-18T10:00:{i:02d}Z url http://h{i}.example.com/x" for i in range(20)],
}


def extract(args, auth, stream, sql, start, end):
    st, r = call(args.url, auth, "POST", f"/api/{ORG}/streams/{stream}/patterns/extract",
                 {"query": {"sql": sql, "start_time": start, "end_time": end, "from": 0, "size": 5000}})
    if st != 200 or not isinstance(r, dict):
        return {"status": st}
    stats = {k: v for k, v in r["statistics"].items() if k != "extraction_time_ms"}
    patterns = [{
        "template": p["template"], "frequency": p["frequency"], "percentage": round(p["percentage"], 6),
        "wildcards": [{"token": w["token"], "mask": w.get("mask")} for w in p.get("wildcard_values", [])],
    } for p in r["patterns"]]
    return {"status": st, "statistics": stats, "config": r["config"],
            "extraction_method": r["extraction_method"], "patterns": patterns}


def ingest(args, auth, stream, messages):
    """Ingest into a fresh stream and return its exact time window."""
    base_us = (int(time.time()) - 600) * 1_000_000
    logs = [{"_timestamp": base_us + n * 1_000_000, "level": "info", "message": m} for n, m in enumerate(messages)]
    st, _ = call(args.url, auth, "POST", f"/api/{ORG}/{stream}/_json", logs)
    if st != 200:
        sys.exit(f"ingest into {stream} answered {st}")
    start, end = base_us, base_us + len(logs) * 1_000_000
    count = {"query": {"sql": f"SELECT count(*) AS c FROM {stream}", "start_time": start,
                       "end_time": end, "from": 0, "size": 10}}
    for _ in range(60):
        _, r = call(args.url, auth, "POST", f"/api/{ORG}/_search", count)
        if isinstance(r, dict) and r.get("hits") and r["hits"][0].get("c") == len(logs):
            return start, end
        time.sleep(1)
    sys.exit(f"stream {stream} never held exactly {len(logs)} rows; use a fresh stream")


def capture(args):
    auth = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()
    messages = [shape(i) for count, shape in SHAPES for i in range(count)]
    start, end = ingest(args, auth, args.stream, messages)
    out = {"all": extract(args, auth, args.stream, f"SELECT * FROM {args.stream}", start, end),
           "messages": messages, "controls": {}, "rules": {}}
    for name, like in CONTROLS.items():
        sql = f"SELECT * FROM {args.stream} WHERE message LIKE '{like}'"
        out["controls"][name] = {"like": like, **extract(args, auth, args.stream, sql, start, end)}
    for name, messages in PROBES.items():
        stream = f"{args.stream}_{name}"
        start, end = ingest(args, auth, stream, messages)
        r = extract(args, auth, stream, f"SELECT * FROM {stream}", start, end)
        out["rules"][name] = {"messages": messages, "analyzed": r["statistics"]["total_logs_analyzed"],
                              # Equal frequencies come back in either order, so they are sorted here.
                              "patterns": sorted(([p["template"], p["frequency"]] for p in r["patterns"]),
                                                 key=lambda p: (-p[1], p[0]))}
    json.dump(out, open(args.out, "w"), indent=1, sort_keys=True)
    print(f"captured {len(out['all'].get('patterns', []))} patterns, {len(out['rules'])} rule probes -> {args.out}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True); p.add_argument("--user", required=True)
    p.add_argument("--password", required=True); p.add_argument("--out", required=True)
    p.add_argument("--stream", default="pattern_shapes")
    capture(p.parse_args())
