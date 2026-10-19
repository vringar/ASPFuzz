# ASPFuzz regression gate

Proves that the current build still finds (A) the Zen2 off-chip BL recovery-mailbox bug and
(B) the original Zen1 on-chip BL CCP copy overflow (board reversing #899, #910, #912).
Firmware is never committed: `bins/` is local only. Needed locally: `bins/on-chip-bl-Ryzen-Zen{1,2}-Desktop`,
`bins/PRIME-B450M-K-II-ASUS-4403.BIN.2nd_half` (A), `bins/PRIME-X370-PRO-ASUS-3803.ROM` (B).

## Usage (from anywhere; uses `target-irq/release/aspfuzz`, override with `ASPFUZZ_BIN=`)
    ./fast_replay.sh [A|B|all]   # FAST tier, ~10-60 s per bug, prints PASS/FAIL, run after every change
    ./run_gate.sh                # full gate: 5 sequential 30 min campaigns per bug (both bugs: up to 5 h)
    GATE_BUGS=A GATE_RUNS=5 GATE_MINUTES=30 GATE_CORES=4 GATE_CONTINUE=0 ./run_gate.sh
    python3 oracle.py {A|B} runs/<run>/solutions [--all] [--t0 EPOCH] [--equals FILE]   # oracle alone, exit 0 = hit
Output: `logs/gate_<stamp>/{gate.log,report.txt,results.tsv,<bug>_<i>.aspfuzz.log,<bug>_<i>/ (hit solution)}` (untracked).
Campaign run dirs: `runs/gate_<bug>_<i>_<stamp>` (wiped at start). Monitor: `tail -f logs/gate_*/gate.log`.

Guards (memory guard #829, enforced in `lib.sh`): MemAvailable > 8 GB and `/proc/pressure/memory` full avg60 < 5 and
no other aspfuzz / port 1337 free before every run (waits up to 30 min, else aborts); run aborted if MemAvailable < 3 GB;
`-n 4`; processes are killed by process-group PID only.

## Oracles (`oracle.py`, deterministic, read the saved objective metadata + input)
* A (config `yaml/gate_zen2_mailbox_bl.yaml` = `mailbox_zen2.yaml`, debug off, harness start 0xd302). Hit if either:
  * `A-dos`: ExceptionHandlerMetadata `DATAB` with `lr == 0x5acc` (strd on an unaligned user pointer; thesis cmds 0x5/0x1a/0x19/0x14);
  * `A-write`: AccessObserver `caught_write` with guest pc in {0x5a78, 0x5aa8, 0x5af4} (unvalidated pointer -> arbitrary x86 write).
  Read at pc 0x4dee is reported but not counted. Signatures are the ones in the 2024-12 saved crashes in `runs/` (402 DATAB/lr 0x5acc;
  writes at 0x5a78/0x5aa8/0x5af4 and read 0x4dee) and match thesis p.63.
* B (config `yaml/gate_zen1_ccp_overflow.yaml` = `ryzen_zen1_desktop_parse_asp_flash.yaml` with `forbidden_memcopies` emptied so the
  objective is the thesis one, PC leaving [0, 0xffff0000)). Hit if RegisterMetadata `pc < 0xffff0000` and `lr == 0xffff715c`
  (the `load LR from stack to PC` site of Zen1 load_entry) and the input's Header Entry size dword (input offset 0x654 =
  flash 0x361414) is >= 0x80000000.

## Fast tier
* A: `reproducers/A_dos_cmd5_unaligned.bin`, `A_write_pc5aa8.bin` (16 B = psp is_master, ptr lo, ptr hi, mailbox word), taken from the
  saved 2024-12-19 solutions `242699bdaf610cb2` / `b8a5ad4206ee4dae`. The historical files use an older field order
  `[psp][word][lo][hi]`; they are re-ordered to the current `[psp][lo][hi][word]`, and hi is set to 1 for the write case so the pointer
  lands in the AccessObserver window (0xfffd...). `reproducers/not_reproducing/A_write_pc5a78.bin` (cmd 0x19) does NOT trigger on the
  current build (the 0x5a78 / 0x5af4 write PCs are still in the oracle but have no saved reproducer that works today).
* B: `make_repro_b.py` builds it at run time from the local flash image (benign extracted seed with the entry-size dword set to
  0xffffffff). Not stored, it contains flash bytes.
* Each reproducer runs in its own aspfuzz process: once the write reproducer failed to trigger when loaded in the same process after the
  DATAB (DoS) one (1 of 4 trials; possible state leak after a crash, not investigated). Startup time varies (2-32 s seen), limit 55 s each.
* The reproducer is loaded as an initial input, `aspfuzz -n 0` runs, and the oracle must match a saved solution that is byte-identical to
  the reproducer (a mutated descendant does not count). Limit 55 s per bug.

## Campaigns
Fresh corpus per campaign: no `initial_inputs` in the gate yamls (checked by the runner), only the benign extracted seed (B) /
all-zero input (both). LibAFL seeds from the nanosecond clock + client id, so every run has a different seed. TTF = solution file mtime
minus process launch (includes ~3-6 s QEMU start). Default stops a campaign at its first hit; `GATE_CONTINUE=1` runs the full 30 min.
Pass = hits >= 4 of 5 per bug; otherwise the report states hits and TTFs as measured (oracle is never tuned).

## Known limits
* Bug B2 (source-address mask, objective writes in [0x7fffff00,0x80037f00]) and Zen+ are not gated.
* Zen1 on-chip BL and flash are local; no saved historical Zen1 solution exists (none in `runs/`), the B reproducer is crafted from the
  thesis signature and the fuzzer's own objective (campaign finds it in ~2-30 s).
* qemu-psp e9d4673a CCP XTS/DES3/ECC error reporting could shift oracle paths; not observed for A or B.
