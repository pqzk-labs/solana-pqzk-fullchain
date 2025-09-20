#!/usr/bin/env bash
# Bench runner: run upload + finalize N times; results appended to examples/benchmarks/results.csv

set -u

RUNS="${1:-100}"
CLI_DIR="examples/cli-chat"
CSV_PATH="examples/benchmarks/results.csv"

trap 'echo; echo "[ABORT] interrupted"; exit 130' INT TERM

echo "[INFO] Target runs: ${RUNS}"
echo "[INFO] CLI dir    : ${CLI_DIR}"
echo "[INFO] CSV output : ${CSV_PATH}"
mkdir -p "$(dirname "$CSV_PATH")"

echo "[INFO] Pre-flight: setup ..."
npm --prefix "$CLI_DIR" run setup >/dev/null 2>&1 || true
echo "[INFO] Pre-flight: keys"
if ! npm --prefix "$CLI_DIR" run keys; then
  echo "[ERR] key setup failed; abort"
  exit 1
fi

succ=0
fail=0

for i in $(seq 1 "$RUNS"); do
  echo "================ ITER $i/$RUNS ================"
  echo "[STEP] upload"
  if ! npm --prefix "$CLI_DIR" run upload; then
    echo "[WARN] upload failed (iter $i); skipping finalize"
    fail=$((fail+1))
    sleep 10
    continue
  fi

  echo "[STEP] finalize"
  if npm --prefix "$CLI_DIR" run finalize; then
    succ=$((succ+1))
  else
    echo "[WARN] finalize failed (iter $i)"
    fail=$((fail+1))
  fi

  sleep 10
done

echo "---------------- SUMMARY ----------------"
echo "success: $succ"
echo "failed : $fail"
echo "CSV    : $CSV_PATH"
echo "-----------------------------------------"
