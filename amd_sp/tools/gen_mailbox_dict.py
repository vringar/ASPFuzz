#!/usr/bin/env python3
"""Turn the librarian's Zen2 SecOS mailbox catalog (JSON, AMD-derived, local only) into the compact dictionary
the mailbox mutator loads (yaml key `mailbox_dict`). Usage: gen_mailbox_dict.py catalog.json > dict.json
Do not commit the output."""
import json, re, sys

cat = json.load(open(sys.argv[1]))
SIZES = {"u8": 1, "u32": 4, "u64": 8}
cmds = []
for c in cat["commands"]:
    fields = []
    for f in c.get("arg_layout") or []:
        t = str(f.get("type", "")).split()[0]
        if t in SIZES and isinstance(f.get("offset"), int):
            fields.append({"offset": f["offset"], "size": SIZES[t]})
    cmds.append({"id": c["id"], "fields": fields})
handled = [c for c in cmds]
neg = [{"id": i, "fields": []} for i in (0, 1, 4, 8, 0x2b, 0x2c, 0x2e, 0x2f)
       if i not in {c["id"] for c in cmds}]
d = cat.get("suggested_fuzz_dictionary", {})
json.dump({
    "commands": handled + neg,
    "values": [v for v in d.get("sizes", []) if isinstance(v, int)],
    "buf_lo_low12": [v for v in d.get("buf_lo_low12", []) if isinstance(v, int)],
}, sys.stdout, indent=1)
