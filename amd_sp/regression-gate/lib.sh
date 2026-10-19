# Shared helpers for fast_replay.sh and run_gate.sh (sourced). Run from anywhere.
GATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AMD_SP="$(dirname "$GATE_DIR")"
GATE_CORES="${GATE_CORES:-4}"          # aspfuzz -n (memory guard #829: 4 max)
BIN_SRC="${ASPFUZZ_BIN:-$AMD_SP/../target-irq/release/aspfuzz}"
SCRATCH="${GATE_SCRATCH:-${TMPDIR:-/tmp}/aspfuzz-gate.$$}"
mkdir -p "$SCRATCH" "$GATE_DIR/logs"

# copy the binary once so a concurrent rebuild cannot change it under a running gate
prepare_bin() {
  [ -x "$BIN_SRC" ] || { echo "no aspfuzz binary at $BIN_SRC (set ASPFUZZ_BIN)"; return 1; }
  BIN="$SCRATCH/aspfuzz"; cp -f "$BIN_SRC" "$BIN"
}

elapsed() { awk -v a="$1" -v b="$(date +%s.%N)" 'BEGIN{printf "%d", b-a}'; }
memavail_kb() { awk '/MemAvailable/{print $2}' /proc/meminfo; }
psi_full60() { sed -n 's/^full.*avg60=\([0-9.]*\).*/\1/p' /proc/pressure/memory; }

# memory guard #829: MemAvailable > 8 GB and full avg60 < 5 before a run, one aspfuzz at a time
guard_ok() {
  [ "$(memavail_kb)" -gt 8000000 ] || { echo "guard: MemAvailable < 8 GB"; return 1; }
  awk -v p="$(psi_full60)" 'BEGIN{exit !(p<5)}' || { echo "guard: memory PSI full avg60 >= 5"; return 1; }
  if pgrep -x aspfuzz >/dev/null; then echo "guard: another aspfuzz is running"; return 1; fi
  if ss -ltn 2>/dev/null | grep -q ':1337 '; then echo "guard: broker port 1337 busy"; return 1; fi
}
wait_guard() {  # wait up to $1 s for the guard
  local end=$((SECONDS + $1))
  until guard_ok; do [ $SECONDS -ge $end ] && return 1; sleep 15; done
}

# start_aspfuzz YAML RUN_NAME LOG [CORES] -> sets PGID, T0 (epoch seconds)
start_aspfuzz() {
  local yaml="$1" run="$2" log="$3" cores="${4:-$GATE_CORES}" maxs="${5:-1900}"
  rm -rf "$AMD_SP/runs/$run"
  T0=$(date +%s.%N)
  pushd "$AMD_SP" >/dev/null
  PROJECT_DIR="$AMD_SP" RUST_LOG=info setsid nohup nice -n 19 \
    timeout -s KILL "$maxs" "$BIN" -n "$cores" -y "$yaml" -r "$run" >"$log" 2>&1 &
  PGID=$!
  popd >/dev/null
  sleep 0.5
  # the group must be led by that PID (setsid did not fork), else we could not kill it by PID
  [ "$(ps -o pgid= -p "$PGID" | tr -d ' ')" = "$PGID" ] || { echo "start_aspfuzz: pid $PGID is not a group leader"; stop_aspfuzz; return 1; }
}
# kill the process group of the run by PID (never by name)
stop_aspfuzz() {
  [ -n "${PGID:-}" ] || return 0
  kill -KILL -- "-$PGID" 2>/dev/null
  for _ in $(seq 150); do pgrep -x aspfuzz >/dev/null || break; sleep 0.2; done
  PGID=""
}
# with_initial_inputs SRC_YAML DST_YAML DIR : add input.initial_inputs: [DIR]
with_initial_inputs() {
  python3 - "$1" "$2" "$3" <<'P'
import sys,re
s=open(sys.argv[1]).read()
assert not re.search(r'(?m)^\s*initial_inputs:', s)
s=re.sub(r'(?m)^input:[^\n]*\n', lambda m: m.group(0)+'  initial_inputs:\n    - '+sys.argv[3]+'\n', s, count=1)
open(sys.argv[2],'w').write(s)
P
}
