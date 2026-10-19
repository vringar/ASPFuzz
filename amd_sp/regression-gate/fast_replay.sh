#!/usr/bin/env bash
# FAST tier: replay saved reproducer input(s) through the current build and assert the oracle.
# usage: fast_replay.sh [A|B|all]   (default all)   prints PASS/FAIL per bug, exit 0 only if all PASS
# Budget < 1 min per bug: the reproducer is loaded as an initial input (alongside the benign zero input),
# aspfuzz -n 0 runs until the oracle matches a saved solution that is byte-identical to the reproducer.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
WHICH="${1:-all}"; LIMIT="${FAST_LIMIT:-55}"
prepare_bin || exit 2
trap 'stop_aspfuzz' EXIT

replay() {  # BUG YAML REPRO...
  local bug="$1" yaml="$2"; shift 2
  guard_ok || { echo "FAIL $bug (guard: $(guard_ok 2>&1))"; return 1; }
  local d="$SCRATCH/init_$bug" run="gate_fast_$bug" sol="$AMD_SP/runs/gate_fast_$bug/solutions"
  rm -rf "$d"; mkdir -p "$d"; local r
  for r in "$@"; do cp "$r" "$d/$(basename "$r")"; done
  with_initial_inputs "$yaml" "$SCRATCH/fast_$bug.yaml" "$d"
  start_aspfuzz "$SCRATCH/fast_$bug.yaml" "$run" "$GATE_DIR/logs/fast_$bug.log" 0 $((LIMIT + 10))
  local ok=0 res=""
  while [ "$(elapsed "$T0")" -lt "$LIMIT" ]; do
    ok=0; res=""
    for r in "$@"; do
      if o=$(python3 "$GATE_DIR/oracle.py" "$bug" "$sol" --t0 "$T0" --equals "$r" 2>/dev/null); then ok=$((ok+1)); res="$res
    $(basename "$r"): $o"; else res="$res
    $(basename "$r"): no oracle hit"; fi
    done
    [ "$ok" = "$#" ] && break
    sleep 1
  done
  local el; el=$(elapsed "$T0")
  stop_aspfuzz
  echo "bug $bug: $ok/$# reproducers trigger the oracle (${el}s):$res"
  [ "$ok" = "$#" ] && echo "PASS $bug" || echo "FAIL $bug"
  [ "$ok" = "$#" ]
}

rc=0
if [ "$WHICH" = A ] || [ "$WHICH" = all ]; then
  # one aspfuzz per reproducer: a crashing input (DATAB) ahead of it in the same process can change the outcome
  for r in "$GATE_DIR"/reproducers/A_*.bin; do
    replay A "$AMD_SP/yaml/gate_zen2_mailbox_bl.yaml" "$r" || rc=1
  done
fi
if [ "$WHICH" = B ] || [ "$WHICH" = all ]; then
  FLASH="$AMD_SP/bins/PRIME-X370-PRO-ASUS-3803.ROM"
  if [ ! -f "$FLASH" ]; then echo "BLOCKED B: missing local input $FLASH (and bins/on-chip-bl-Ryzen-Zen1-Desktop)"; rc=1
  else
    python3 "$GATE_DIR/make_repro_b.py" "$FLASH" "$SCRATCH/B_entry_size_ffffffff.bin"
    replay B "$AMD_SP/yaml/gate_zen1_ccp_overflow.yaml" "$SCRATCH/B_entry_size_ffffffff.bin" || rc=1
  fi
fi
exit $rc
