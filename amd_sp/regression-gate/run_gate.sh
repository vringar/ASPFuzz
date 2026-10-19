#!/usr/bin/env bash
# Regression gate runner: per bug N independent campaigns (default 5 x 30 min), sequential, one aspfuzz at a time.
# usage: run_gate.sh            (both bugs)   |   GATE_BUGS=A run_gate.sh
# env:   GATE_RUNS=5  GATE_MINUTES=30  GATE_BUGS="A B"  GATE_CORES=4  GATE_CONTINUE=0|1  ASPFUZZ_BIN=...
#        GATE_CONTINUE=1 keeps fuzzing after the first hit until the full time budget (default: stop at first hit,
#        TTF is the same either way).
# Each campaign: fresh run directory (runs/ is wiped for that name), fresh corpus = benign initial inputs only
# (yaml has no initial_inputs; LibAFL seeds its RNG from the nanosecond clock + client id, so every run differs).
# Pass criterion (Stefan, board #899): >= 4 of 5 campaigns hit the oracle. The oracle is oracle.py, unchanged.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
RUNS="${GATE_RUNS:-5}"; MIN="${GATE_MINUTES:-30}"; BUGS="${GATE_BUGS:-A B}"; CONT="${GATE_CONTINUE:-0}"
STAMP=$(date +%Y%m%d_%H%M%S); OUT="$GATE_DIR/logs/gate_$STAMP"; mkdir -p "$OUT"
REPORT="$OUT/report.txt"; RES="$OUT/results.tsv"; : >"$RES"
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/gate.log"; }
prepare_bin || exit 2
trap 'stop_aspfuzz; say "gate interrupted"' INT TERM
trap 'stop_aspfuzz' EXIT
say "gate start: runs=$RUNS minutes=$MIN bugs=[$BUGS] cores=$GATE_CORES bin=$BIN_SRC (sha256 $(sha256sum "$BIN_SRC" | cut -c1-12))"

yaml_for() { case "$1" in A) echo "$AMD_SP/yaml/gate_zen2_mailbox_bl.yaml";; B) echo "$AMD_SP/yaml/gate_zen1_ccp_overflow.yaml";; esac; }
need_for()  { case "$1" in A) echo "$AMD_SP/bins/on-chip-bl-Ryzen-Zen2-Desktop $AMD_SP/bins/PRIME-B450M-K-II-ASUS-4403.BIN.2nd_half";;
                          B) echo "$AMD_SP/bins/on-chip-bl-Ryzen-Zen1-Desktop $AMD_SP/bins/PRIME-X370-PRO-ASUS-3803.ROM";; esac; }

for bug in $BUGS; do
  yaml=$(yaml_for "$bug")
  for f in $(need_for "$bug"); do [ -f "$f" ] || { say "BLOCKED bug $bug: missing local input $f"; echo -e "$bug\t-\tBLOCKED\t-\t-" >>"$RES"; continue 2; }; done
  grep -Eq '^\s*initial_inputs:' "$yaml" && { say "ABORT: $yaml seeds initial_inputs (a replayed crash would not count)"; exit 3; }
  for i in $(seq "$RUNS"); do
    wait_guard 1800 || { say "ABORT: memory guard did not clear for 30 min"; exit 4; }
    run="gate_${bug}_${i}_$STAMP"; log="$OUT/${bug}_$i.aspfuzz.log"
    start_aspfuzz "$yaml" "$run" "$log" "$GATE_CORES" $((MIN * 60 + 120)) || exit 5
    say "bug $bug run $i/$RUNS started (run dir runs/$run, pid group $PGID)"
    sol="$AMD_SP/runs/$run/solutions"; hit=""; abort=""; checked=0
    while [ "$(elapsed "$T0")" -lt $((MIN * 60)) ]; do
      sleep 2
      if [ $checked = 0 ] && [ "$(elapsed "$T0")" -ge 2 ]; then   # benign-corpus audit, logged (files present at start)
        checked=1; ls "$AMD_SP/runs/$run/inputs" 2>/dev/null | head -8 | tr '\n' ' ' >"$OUT/${bug}_$i.initial_corpus.txt"
      fi
      [ "$(memavail_kb)" -lt 3000000 ] && { abort="MemAvailable < 3 GB"; break; }
      if o=$(python3 "$GATE_DIR/oracle.py" "$bug" "$sol" --t0 "$T0" 2>/dev/null); then
        hit="$o"; [ "$CONT" = 1 ] || break
      fi
    done
    [ -z "$hit" ] && hit=$(python3 "$GATE_DIR/oracle.py" "$bug" "$sol" --t0 "$T0" 2>/dev/null)  # last look before kill
    nsol=$(ls "$sol" 2>/dev/null | grep -vc '^\.')
    # keep evidence: hit solution metadata (inputs for B contain flash bytes: logs/ is untracked)
    if [ -n "$hit" ]; then
      f=$(sed -n 's/.* file=\([^ ]*\) .*/\1/p' <<<"$hit"); mkdir -p "$OUT/${bug}_$i"
      cp -f "$sol/$f" "$OUT/${bug}_$i/" 2>/dev/null; cp -f "$sol"/.${f}*.metadata "$OUT/${bug}_$i/" 2>/dev/null
    fi
    stop_aspfuzz
    if [ -n "$abort" ]; then say "bug $bug run $i ABORTED: $abort"; echo -e "$bug\t$i\tABORT\t-\t$abort" >>"$RES"; exit 6; fi
    if [ -n "$hit" ]; then
      ttf=$(sed -n 's/.* t=\([0-9.]*\).*/\1/p' <<<"$hit"); kind=$(sed -n 's/.* kind=\([^ ]*\).*/\1/p' <<<"$hit")
      say "bug $bug run $i HIT ttf=${ttf}s kind=$kind ($nsol solution files so far)"; echo -e "$bug\t$i\tHIT\t$ttf\t$kind" >>"$RES"
    else
      say "bug $bug run $i MISS after ${MIN} min ($nsol solution files, none matching the oracle)"; echo -e "$bug\t$i\tMISS\t-\t-" >>"$RES"
    fi
  done
done

python3 - "$RES" "$RUNS" "$MIN" >"$REPORT" <<'P'
import sys,statistics as st
rows=[l.rstrip('\n').split('\t') for l in open(sys.argv[1])]; n=int(sys.argv[2]); mins=sys.argv[3]
bugs=sorted({r[0] for r in rows}); allok=True
print("ASPFuzz regression gate: %s campaigns x %s min per bug, pass = >= 4 hits of 5 (board #899)" % (n,mins))
for b in bugs:
    rs=[r for r in rows if r[0]==b]
    if any(r[2]=='BLOCKED' for r in rs): print("bug %s: BLOCKED (missing local input)"%b); allok=False; continue
    hits=[float(r[3]) for r in rs if r[2]=='HIT']; kinds=sorted({r[4] for r in rs if r[2]=='HIT'})
    need=-(-4*n//5); ok=len(hits)>=need; allok&=ok
    line="bug %s: hits %d/%d  TTF per hit %s s" % (b,len(hits),len(rs),[round(h) for h in hits])
    if hits: line+="  median %.0f s  max %.0f s  kinds %s" % (st.median(hits),max(hits),kinds)
    print(line+"  => "+("PASS" if ok else "FAIL (hit rate below 4/5, need %d of %d; reported as measured, oracle not tuned)"%(need,n)))
    if len(hits)<len(rs): print("  misses: runs %s ended without an oracle hit within %s min" % ([r[1] for r in rs if r[2]!='HIT'],mins))
print("GATE "+("PASS" if allok else "FAIL"))
P
cat "$REPORT" | tee -a "$OUT/gate.log"
grep -q "^GATE PASS" "$REPORT"
