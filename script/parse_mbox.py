#!python
## parse_mbox 0x4000123123
# Response Set 1
# Restart required 0

import ctypes
import struct
import sys

assert len(sys.argv) == 2, "Please pass an argument"
# uint32_t:16	Status/Data
# uint32_t:8	Command ID
# uint32_t:4	Alternate_Status
# uint32_t:1	Must be zero
# uint32_t:1	ResetRequired	Set by the target to indicate that the host must execute warm reset if FW corruption is detected.
# uint32_t:1	Recovery	Set by the target to indicate that the host has to execute FW recovery sequence
# uint32_t:1	CmdOrRspns	Command = 0 (Written by OS); Response = 1 (Written by PSP upon completion)
class MboxStruct(ctypes.BigEndianStructure):
    _fields_ = [
        ("CmdOrRspns", ctypes.c_uint32, 1),
        ("Recovery", ctypes.c_uint32, 1),
        ("ResetRequired", ctypes.c_uint32, 1),
        ("Reserved", ctypes.c_uint32, 1),
        ("AltStat", ctypes.c_uint32, 4),
        ("CommandId", ctypes.c_uint32, 8),
        ("StatOrDta", ctypes.c_uint32, 16),
    ]


mbox_struct = MboxStruct()

mbox_value = int(sys.argv[1],16)
# then you can pack to it:
struct.pack_into('!I', mbox_struct,
                 0, # offset
                 mbox_value)

print("CmdOrRspns", "Command" if mbox_struct.CmdOrRspns == 0 else "Response")
if mbox_struct.Recovery:
    print("Recovery requested")
if mbox_struct.ResetRequired:
    print("Reset required")
if mbox_struct.Reserved != 0:
    print("Invalid Message")
print("AltStat", mbox_struct.AltStat)
print("CommandId", mbox_struct.CommandId)
print("Data" if mbox_struct.CmdOrRspns == 0 else "Status", mbox_struct.StatOrDta)