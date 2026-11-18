#!/usr/bin/env python3
import argparse, base64, json, re, socket, sys, urllib.error, urllib.request

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call_args(src, start):
    depth, at = 1, start
    while depth and at < len(src):
        depth += {"(": 1, ")": -1}.get(src[at], 0)
        at += 1
    return src[start : at - 1]


def routes(router_src):
    found = set()
    for m in re.finditer(r"\.route\(", router_src):
        args = call_args(router_src, m.end())
        path = re.match(r'\s*"([^"]+)"\s*,', args)
        if not path:
            continue
        params = set(re.findall(r"[{:](\w+)\}?", path.group(1)))
        if re.search(r"\bget\(", args[path.end() :]) and params <= {"org_id"}:
            found.add(re.sub(r"\{org_id\}|:org_id", "default", path.group(1)))
    return sorted(found)


def get(base, path, auth):
    req = urllib.request.Request(base + path, headers={"Authorization": auth})
    try:
        with OPENER.open(req, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()
    except (TimeoutError, socket.timeout):
        # A route that holds the connection open (a stream) is an answer of its own kind.
        return "timeout", b""
    except OSError as err:
        # An unreachable instance is not an answer: two of them would compare as equal.
        sys.exit(f"{base}{path}: {err}")


def shape(body):
    try:
        value = json.loads(body)
    except ValueError:
        return "text"
    if isinstance(value, dict):
        return sorted(value)
    return type(value).__name__


def main():
    ap = argparse.ArgumentParser()
    for flag in ("--router", "--a", "--b", "--user", "--password", "--out"):
        ap.add_argument(flag, required=True)
    args = ap.parse_args()
    auth = "Basic " + base64.b64encode(f"{args.user}:{args.password}".encode()).decode()
    surface = {}
    for route in routes(open(args.router).read()):
        for prefix in ("/api", ""):
            path = prefix + route
            (sa, ba), (sb, bb) = get(args.a, path, auth), get(args.b, path, auth)
            if (sa, sb) != (404, 404):
                if sa != sb:
                    # Only the status and the top-level keys: a body may hold instance data.
                    surface[path] = {"a": sa, "b": sb, "b_shape": shape(bb)}
                break
    json.dump({"differs": surface}, open(args.out, "w"), indent=1, sort_keys=True)
    print(f"{len(surface)} routes answer differently -> {args.out}")


if __name__ == "__main__":
    sys.exit(main())
