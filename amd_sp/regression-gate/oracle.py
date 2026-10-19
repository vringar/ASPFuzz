#!/usr/bin/env python3
"""Deterministic bug oracles for the ASPFuzz regression gate.

usage: oracle.py {A|B} SOLUTIONS_DIR [--t0 EPOCH] [--equals FILE] [--all]

Inspects the saved objectives (<hash>, .<hash>_N.metadata / .<hash>.metadata) of one run and
exits 0 if at least one satisfies the bug signature, 1 otherwise. Prints one line per hit:
    HIT bug=A kind=A-dos file=<hash> t=<mtime-t0 seconds> detail...
Only the first (earliest) hit is printed unless --all.  --t0 makes t relative to the campaign
start; --equals FILE only accepts a solution whose input bytes are identical to FILE (fast tier:
the replayed reproducer itself must trigger the oracle, not a mutated descendant).

Signatures (all taken from objectives the fuzzer itself saved, see README.md):

A  Zen2 off-chip BL recovery mailbox (mailbox_zen2 harness, start 0xd302)
   A-dos    ExceptionHandlerMetadata: triggered_exception == DATAB and lr == 0x5acc
            (strd to an unaligned user pointer; thesis: LR 0x5acc, cmds 0x5/0x1a/0x19/0x14)
   A-write  AccessObserverMetadata.caught_write = [x86 addr, guest pc] with pc in
            {0x5a78 (cmd 0x19), 0x5aa8 (cmd 0x1a), 0x5af4 (cmd 0x14)}
            (unvalidated user pointer -> write of attacker data to an arbitrary x86 address)
   A-read (pc 0x4dee, cmd 0x1a) is reported as detail but does not count on its own.

B  Zen1 on-chip BL load_entry CCP copy overflow (ryzen_zen1 harness)
   RegisterMetadata (taken after the run): pc outside [0xffff0000, 0xffffffff] (PC left the
   on-chip ROM; the crash module's no_exec region is [0, 0xffff0000)), lr == 0xffff715c (the
   `load LR from stack to PC` site of Zen1 load_entry), AND the saved input has the Header Entry
   size dword (input offset 0x640+0x14 = flash 0x361414) >= 0x80000000 (signed/unsigned check bug).
"""
import argparse
import glob
import json
import os
import struct
import sys

A_WRITE_PCS = {0x5A78, 0x5AA8, 0x5AF4}
A_READ_PC = 0x4DEE
A_DOS_LR = 0x5ACC
B_LR = 0xFFFF715C
B_ROM_BASE = 0xFFFF0000
B_SIZE_OFF = 0x640 + 0x14  # FET 0x40 + combo dir 0x300 + dir 0x300 = 0x640, then entry header
MD = "metadata"
EH = "libasp::exception_handler::ExceptionHandlerMetadata"
AO = "libasp::bindings::AccessObserverMetadata"
RG = "libasp::gen_metadata::RegisterMetadata"
MB = "libasp::emulator_module::MiscMetadata"


def hx(v):
    return int(v, 16) if isinstance(v, str) else int(v)


def check_a(m, _data):
    eh = m.get(EH)
    if eh and eh[1].get("triggered_exception") == "DATAB" and hx(eh[1]["registers"]["lr"]) == A_DOS_LR:
        return "A-dos", "DATAB lr=0x5acc" + _mbox(m)
    ao = m.get(AO)
    if ao:
        cw = ao[1].get("caught_write")
        if cw and cw[1] in A_WRITE_PCS:
            cr = ao[1].get("caught_read")
            extra = " +read@%#x" % cr[1] if cr and cr[1] == A_READ_PC else ""
            return "A-write", "write x86 addr=%#x pc=%#x%s%s" % (cw[0], cw[1], extra, _mbox(m))
    return None


def _mbox(m):
    mb = m.get(MB)
    if not mb:
        return ""
    v = mb[1]["mailbox_values"]
    return " mbox_out=%#010x lo=%#010x" % (v["mbox"], v["ptr_lower"])


def check_b(m, data):
    rg = m.get(RG)
    if not rg or data is None or len(data) < B_SIZE_OFF + 4:
        return None
    r = rg[1]
    pc, lr = hx(r["pc"]), hx(r["lr"])
    size = struct.unpack_from("<I", data, B_SIZE_OFF)[0]
    if pc < B_ROM_BASE and lr == B_LR and size >= 0x80000000:
        return "B-pc-leaves-rom", "pc=%#x lr=%#x sp=%s entry_size=%#x" % (pc, lr, r["sp"], size)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bug", choices=["A", "B"])
    ap.add_argument("sol_dir")
    ap.add_argument("--t0", type=float, default=0.0)
    ap.add_argument("--equals")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    want = open(a.equals, "rb").read() if a.equals else None
    hits = []
    for mf in glob.glob(os.path.join(a.sol_dir, ".*.metadata")):
        name = os.path.basename(mf)[1:-len(".metadata")]
        base = name.rsplit("_", 1)[0] if name.rsplit("_", 1)[-1].isdigit() else name
        # '<hash>' or '<hash>-N' (duplicates) or '<hash>_N' (metadata suffix)
        inp = os.path.join(a.sol_dir, base)
        data = open(inp, "rb").read() if os.path.exists(inp) else None
        if want is not None and data != want:
            continue
        try:
            m = json.load(open(mf))[MD]["map"]
        except (OSError, ValueError, KeyError):
            continue  # partially written
        r = (check_a if a.bug == "A" else check_b)(m, data)
        if r:
            hits.append((os.path.getmtime(mf) - a.t0, base, r))
    hits.sort()
    for t, base, (kind, detail) in (hits if a.all else hits[:1]):
        print("HIT bug=%s kind=%s file=%s t=%.1f %s" % (a.bug, kind, base, t, detail))
    sys.exit(0 if hits else 1)


if __name__ == "__main__":
    main()
