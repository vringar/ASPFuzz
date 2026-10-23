#!/usr/bin/env bash
# Safety net: both old-bug targets (gate A and B), 5 runs each on the current build; fails if any run misses.
# Prints the time to find for every run. Usage: verify.sh   (ASPFUZZ_BIN overrides the binary)
set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
export ASPFUZZ_BIN="${ASPFUZZ_BIN:-$(cd .. && pwd)/../target/release/aspfuzz}"
GATE_RUNS=5 ./run_gate.sh || true
res="$(ls -td logs/gate_*/ | head -n 1)results.tsv"
awk -F'\t' '
  { n[$1]++; if ($3 == "HIT") { h[$1]++; t[$1] = t[$1] " " $4 "s" } }
  END {
    ok = (n["A"] == 5 && n["B"] == 5)
    for (b in n) { printf "bug %s: %d/%d hits, time to find:%s\n", b, h[b], n[b], t[b]; if (h[b] != 5) ok = 0 }
    print "VERIFY " (ok ? "PASS" : "FAIL"); exit !ok
  }' "$res"
