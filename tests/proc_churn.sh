#!/usr/bin/env bash
# Generate rapid short-lived processes so Montauk flags PROC CHURN.
set -euo pipefail

events=${1:-64}
delay=${2:-0.02}
runtime=${3:-0.03}

tmp_script=$(mktemp /tmp/montauk_churn.XXXXXX.sh)
cleanup() {
  rm -f "$tmp_script"
}
trap cleanup EXIT

cat >"$tmp_script" <<'EOF'
#!/usr/bin/env bash
sleep "${PROC_CHURN_RUNTIME:-0.03}"
EOF
chmod +x "$tmp_script"

for _ in $(seq 1 "$events"); do
  PROC_CHURN_RUNTIME="$runtime" bash "$tmp_script" >/dev/null 2>&1 &
  sleep "$delay"
done

wait
