# 📊 Benchmarks (Compute Units)

Simple tools to measure compute units (CU) for:
- finalize_sig (SLH‑DSA verify + ChatMsg write)
- verify_stark (STARK verify)

Each run appends results to examples/benchmarks/results.csv in: timestamp,phase,cu,cu_limit,txsig

## 📂 Files
- finalize.ts.txt — instrumented finalize.ts that writes CSV lines.
- run-bench.sh — runs upload + finalize N times.
- results.csv — combined CSV output.
- results-finalize-only.csv, results-verify-only.csv — sample results.
- statistics.txt — sample summary from 100 runs.

## ⚡ Quick Start
1. Enable the instrumented finalize:
```
cp examples/benchmarks/finalize.ts.txt examples/cli-chat/src/finalize.ts
```
2. Make the runner executable (first time only):
```
chmod +x examples/benchmarks/run-bench.sh
```
3. Run N iterations (default: 100):
```
examples/benchmarks/run-bench.sh          # 100 runs
examples/benchmarks/run-bench.sh 200      # 200 runs
```
4. Check results:
`examples/benchmarks/results.csv`

## 📝 Notes
- Benchmarks run on devnet; CU varies with cluster load.
- You can adjust requested heap/CU limits inside: examples/cli-chat/src/finalize.ts
