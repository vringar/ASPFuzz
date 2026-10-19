#!/usr/bin/env python3
"""Build the bug-B reproducer from the LOCAL flash image (never committed; output goes to the path given).
Input layout = gate_zen1_ccp_overflow.yaml flash.input: FET(0x20000,0x40) ComboDir(0xc0000,0x300)
Dir(0xd1000,0x300) EntryHeader(0x361400,0x100) -> 0x740 bytes. Only change vs. the benign seed:
the Header Entry size dword (header+0x14, input offset 0x654) is set to 0xffffffff."""
import struct, sys
img = open(sys.argv[1], "rb").read()
seed = b"".join(img[a:a + n] for a, n in [(0x20000, 0x40), (0xC0000, 0x300), (0xD1000, 0x300), (0x361400, 0x100)])
assert len(seed) == 0x740
r = bytearray(seed)
struct.pack_into("<I", r, 0x654, 0xFFFFFFFF)
open(sys.argv[2], "wb").write(r)
