#!/bin/bash
# Control pair for o2_parity.py: the same binary twice must agree; a mutated fixture must differ.
# Usage: control.sh <openobserve binary> <empty work dir>
set -u
BIN=$1; W=$2; HERE=$(cd "$(dirname "$0")" && pwd)
C="--user parity@example.com --password Parity-Lab-123456"
PIDS=()
start() {
  mkdir -p "$W/data$1"
  (cd "$W" && ZO_ROOT_USER_EMAIL=parity@example.com ZO_ROOT_USER_PASSWORD=Parity-Lab-123456 \
    ZO_DATA_DIR="$W/data$1/" ZO_HTTP_PORT=$2 ZO_GRPC_PORT=$3 ZO_TELEMETRY=false \
    exec "$BIN" > "$W/o2-$1.log" 2>&1) &
  PIDS+=($!)
}
trap 'kill "${PIDS[@]}" 2>/dev/null' EXIT
start A 5081 5082; start B 5083 5084; start C 5085 5086
for p in 5081 5083 5085; do
  for _ in $(seq 1 60); do curl -s --noproxy '*' "http://127.0.0.1:$p/healthz" | grep -q ok && break; sleep 2; done
done
python3 -I "$HERE/o2_parity.py" capture --url http://127.0.0.1:5081 $C --out "$W/a.json"
sleep 70
python3 -I "$HERE/o2_parity.py" capture --url http://127.0.0.1:5083 $C --out "$W/b.json"
python3 -I "$HERE/o2_parity.py" capture --url http://127.0.0.1:5085 $C --mutate --out "$W/mut.json"
echo "== same binary twice (must be 0 differ)"
python3 -I "$HERE/o2_parity.py" diff "$W/a.json" "$W/b.json"; SAME=$?
echo "== mutated fixture (must differ)"
python3 -I "$HERE/o2_parity.py" diff "$W/a.json" "$W/mut.json"; MUT=$?
[ $SAME -eq 0 ] && [ $MUT -eq 1 ]
