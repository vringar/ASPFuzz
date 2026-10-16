# Harness notes (Zen2, SecOS and off-chip BL)

Facts only; guesses are marked. Addresses are guest addresses of the Zen2 firmware set listed in `repro/README.md`
(flash `PRIME-B450M-K-II-ASUS-4403.BIN(.2nd_half)`, on-chip BL `e06f2a3e`, off-chip BL `6f94447d`).
Firmware is never committed (`bins/` is local only).

## Configs (`yaml/`)
| yaml | what it fuzzes | notes |
|---|---|---|
| `ryzen_zen{1,2}_desktop_parse_asp_flash.yaml` | on-chip BL flash directory parse | tunnels: fletcher32 CopyRegister at 0xffff2058/0xffff2114 |
| `offchip_bhd_zen2.yaml` / `_parse` / `_full` | off-chip BL `$BL2` directory (`psp_flash_get_bhd_dir` 0x317c) | `_full` = full 0x278 B dir + `fixed_length_mutators`; saturates at ~566 edges: the dir is only copied/filtered (builder 0x4b94 -> 16-slot table at RAM 0x11bc0) |
| `offchip_bl2_users.yaml` | the `$RA2` table at `cold_boot` | bare memcpy, 287 edges, nothing to find |
| `offchip_to_onchip.yaml` | snapshot at main epilogue 0x1546 | prototype, did not reach the snapshot (second-timer delay) at the time |
| `secos*.yaml`, `secos_mbox.yaml` | SecOS mailbox command fn 0x200b4c..0x200e70 | `secos_mbox` snapshots at 0x20298a (after the SecOS app attach inits); tunnels 0xe101d8 etc. no longer needed with qemu-psp IC v5+ |
| `secos_bootargs.yaml` | boot-args `$RA2` validator 0xe04f00 | snapshot 0xe07bb4, `WriteMemory` tunnel patches in a call; 36 edges, outcomes 0x80001001/0x80001011/0 |

## SecOS facts (Zen2 kernel 18a38127 / app fa66c9c4, measured on the QEMU model)
- IC base 0x03010000 (enable +0x200.., ACK +0x2b0, PEN +0x2c0, ID +0x2c4). FIQ dispatch loop at 0xf60 (id read at 0xf6e), idle fn 0x1d68 (WFI 0x1db2). irq table (idtab) at PA 0x6a7c, 0x61 = unattached.
- Attached ids after init: 0x10->slot 0x1a, 0x3c->0x1b, 0x31->0x1c, 0x34->0x1d, 0x77->0x19. Enabled set {0x10,0x1d,0x31,0x34,0x3a,0x60,0x70,0x74}. Slots are posted at 0x3c88 from the FIQ loop.
- Mailbox command path is polled in the harness: replies are `0x80000000 + status` (cmd 0x1a -> 9, 0x1c -> 4). A pending command has bit 31 clear (`cmd << 16`). The doorbell interrupt (guess: id 0x3c) is not required for the reply.
- The boot-args page is PA 0x4f000 (SecOS VA 0x208000); `$RA2` table at +0x52c (n at +0x530, 16 B slots from +0x534). Validator `0xe04f00` is called only from `0xe0c5a8`.

## Run recipe
`cd amd_sp && PROJECT_DIR=$PWD target/release/aspfuzz -n 4 -y yaml/<cfg>.yaml -r <run>` (binary is at the workspace root `target/`).
Broker port 1337 is fixed: one run at a time; kill leftovers before a new run. Extra QEMU args: env `ASPFUZZ_EXTRA_QEMU_ARGS`.
Read-watch logger (inert): env `ASPFUZZ_READWATCH`. Opt-in diagnostics: `--verify-reset`.

## Known harness caveats
- On a per-exec timeout the snapshot is now restored (it was skipped before); timeouts cost 10 s each.
- Mutation changes the injected mailbox word; classify iterations by the injected word0 when counting replies.
