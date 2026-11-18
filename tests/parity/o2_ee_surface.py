#!/usr/bin/env python3
# Probes every parameter-free GET route of the router on two running instances and records
# where they differ. Usage:
#   o2_ee_surface.py --router <router/mod.rs> --a <url> --b <url> --user U --password P --out F
import argparse, base64, json, re, sys, urllib.error, urllib.request

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def routes(router_src):
    found = set()
    pattern = r'\.route\(\s*"([^"]+)"\s*,\s*((?:[^()]|\([^()]*\))*?)\)\s*[\n.]'
    for m in re.finditer(pattern, router_src):
        params = set(re.findall(r"[{:](\w+)\}?", m.group(1)))
        if re.search(r"\bget\(", m.group(2)) and params <= {"org_id"}:
            found.add(re.sub(r"\{org_id\}|:org_id", "default", m.group(1)))
    return sorted(found)


def get(base, path, auth):
    req = urllib.request.Request(base + path, headers={"Authorization": auth})
    try:
        with OPENER.open(req, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()
    except OSError:
        return 0, b""


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
