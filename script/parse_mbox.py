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


CommandMap = {
    0x02: [
        "MboxBiosCmdSmmInfo",
        "Provides details on SMM memory area reserved for PSP. It includes the physical addresses of SMM Base and PSP SMM data region and the length of PSP SMM data region.",
    ],
    0x03: [
        "MboxBiosCmdSxInfo",
        "Notification that the platform is entering S3-suspend state.",
    ],
    0x04: [
        "MboxBiosCmdRsmInfo",
        "Information on BIOS Resume Module stored in SMM memory includes the BIOS resume vector and size of the resume code.",
    ],
    0x05: [
        "MboxBiosCmdPspQuery",
        "Command to get the list of capabilities supported by PSP FW. This is used to communicate if fTPM is supported in PSP FW.",
    ],
    0x06: ["MboxBiosCmdBootDone", "Notification that BIOS has completed BIOS POST."],
    0x14: [
        "MboxBiosCmdHSTIQuery",
        "Command to get HSTI bit field representing the security state of the SOC from the PSP.",
    ],
    0x19: ["MboxBiosCmdGetVersion", "Get FW version."],
    0x1A: [
        "MboxBiosCmdSetFuse",
        "BIOS sends this command to set Field Programmable fuse; only enabled in special released FW.",
    ],
    0x1B: ["MboxBiosCmdLockDFReg", "BIOS will send this command to lock DF registers."],
    0x1C: [
        "MboxBiosCmdClrSmmLock",
        "Command to clear SMMLock register in C6 private memory region.",
    ],
    0x1D: [
        "MboxBiosCmdSetApCsBase",
        "BIOS will send the CS BASE value for AP threads.",
    ],
    0x1E: ["MboxBiosCmdKvmInfo", "KVM required information."],
    0x1F: [
        "MboxBiosCmdLockSpi",
        "BIOS will send this command to lock SPI; X86 must be in SMM mode when sending this command.",
    ],
    0x20: [
        "MboxBiosCmdScreenOnGpio",
        "Report the FCH GPIOs for early turn on eDP panel in S0i3.",
    ],
    0x21: [
        "MboxBiosCmdSpiOpWhiteList",
        "BIOS sends SPI operation whitelist to lock SPI; X86 must be in SMM mode when sending this command; only used in server product",
    ],
    0x22: [
        "MboxBiosCmdPsbAutoFusing",
        "PSP will set the PSB related in the field; used only in non-server products.",
    ],
    0x24: ["MboxBiosCmdRasEinj", "BIOS sends RAS Error Injection action."],
    0x25: ["MboxBiosCmdStopArs", "Command to Stop ARS for RAS feature."],
    0x26: [
        "MboxBiosCmdSetBootPartitionId",
        "BIOS sends this command to PSP to write the ACTIVE_BOOT_PARTITION_ID register.",
    ],
    0x27: ["MboxBiosCmdPspCapsQuery", "BIOS checks PSP NVRAM health."],
    0x2D: [
        "MboxBiosCmdLaterSplFuse",
        "BIOS sends this command to PSP for SPL fuse for anti-rollback feature.",
    ],
    0x2E: [
        "MboxBiosCmdDtpmInfo",
        "BIOS-to-PSP: Command to get dTPM status and event log.",
    ],
    0x2F: [
        "BIOS_CMD_VALIDATE_MAN_OS_SIGNATURE",
        "BIOS-to-PSP: Validate signature of manageability OS image based on header passed by BIOS.",
    ],
    0x30: [
        "MboxBiosCmdLockFCHReg",
        "BIOS-to-PSP: BIOS sends this command to lock FCH PM and IOMux registers.",
    ],
    0x31: [
        "BIOS_CMD_GET_DRTM_INFO",
        "BIOS-to-PSP: Queries updated dRTM information in post dRTM phase.",
    ],
    0x39: [
        "MboxBiosCmdSetRpmcAddress",
        "BIOS-to-PSP: Bios sends this command to PSP to decide which RPMC address to use. Only used in product line.",
    ],
    0x3A: [
        "MboxBiosCmdLockGPIO",
        "A warm reset should be issued after receiving BIOS_MBOX_OK (0) from PSP tOS, otherwise BIOS does nothing. BIOS-to-PSP: BIOS sends this command to PSP to lock GPIO.",
    ],
    0x3F: [
        "MboxBiosCmdSendIvrsAcpiTable",
        "BIOS-to-PSP: BIOS sends IVRS buffer to PSP, PSP saves it, then AMDSL uses another command to retrieve it back to the buffer.",
    ],
    0x40: ["MboxBiosCmdTa", "Send command to TA."],
    0x41: [
        "BIOS_CMD_ACPI_RAS_EINJ",
        "BIOS-to-PSP: Enables/disables ACPI-based RAS EINJ feature.",
    ],
    0x42: ["MboxBiosCmdQueryTCGLog", "BIOS-to-PSP: Queries TCG Log."],
    0x47: [
        "MboxBiosCmdQuerySplFuse",
        "BIOS-to-PSP: Gets the current value of the SPL_F (FW_ROLLBACK_CNT) fuse value.",
    ],
}

mbox_struct = MboxStruct()

mbox_value = int(sys.argv[1], 16)
# then you can pack to it:
struct.pack_into("!I", mbox_struct, 0, mbox_value)  # offset

print("CmdOrRspns", "Command" if mbox_struct.CmdOrRspns == 0 else "Response")
if mbox_struct.Recovery:
    print("Recovery requested")
if mbox_struct.ResetRequired:
    print("Reset required")
if mbox_struct.Reserved != 0:
    print("Invalid Message")
print("AltStat", mbox_struct.AltStat)
print("CommandId", hex(mbox_struct.CommandId))
print("Data" if mbox_struct.CmdOrRspns == 0 else "Status", mbox_struct.StatOrDta)

if mbox_struct.CommandId in CommandMap:
    print("Command name: ", CommandMap[mbox_struct.CommandId][0])
    print("Command Description:", CommandMap[mbox_struct.CommandId][1])
