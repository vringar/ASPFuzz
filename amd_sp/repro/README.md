# Reproduction manifests

One entry per reported result. Firmware blobs are never committed; they are
identified by name and sha256 only. Bulky output (logs, corpora, DrCov) is not
tracked.

Common build: LibAFL `f8bb18828cf8e283fccb23f3a3c2967ff74224f6`
(PSPReverse/LibAFL, `claude/libafl-bump-ic-v5`), which pins qemu-psp
`1d1b8e76b76a1668d1fde5a56a6f496b71ba2565` (`claude/psp-irq-ic-v5`).
Command form (from `amd_sp/`): `PROJECT_DIR=$PWD target/release/aspfuzz -n <cores> -y yaml/<config>.yaml -r <run>`.

Firmware (names/sha256):
- on-chip BL Zen2: `bins/on-chip-bl-Ryzen-Zen2-Desktop` e06f2a3e19ccc676…
- flash `PRIME-B450M-K-II-ASUS-4403.BIN.2nd_half` 208d4c13b77a230f49998732ace0e9c2fd72ceb96e729851e8ed44f4ca75aedc
- flash `PRIME-B450M-K-II-ASUS-4403.BIN` ea7f3c5d5c592ee9d160cd8d7371146ed1c07fe4a49b433098ec66ea090a5e8e
- flash `TUF-GAMING-B450-PLUS-II-ASUS-4202.ROM` 39242a6554159f73479cc2b6f245d53b5d4f3fa2916540ed4cffa738b00bd4db

## IC retirement of tunnel 0xe101d8 (board #515, #535)
60 s, `-n 0`, 0 objectives, 0xe101d8 tunnel removed:

| config | execs | edges | corpus |
|---|---|---|---|
| secos | 21637 | 737 | 46 |
| secos_test | 17759 | 721 | 42 |
| secos_post_0x2 | 11708 | 899 | 42 |
| secos_post_0x2_0x1b | 12907 | 766 | 40 |
| secos_post_0x2_0x1b_0x6 | 3880 (40 s) | 193 | 6 |
| secos_post_0x2_0x28 | 9359 (40 s) | 765 | 39 |
| secos_post_0x2_0x50 | 9355 (40 s) | 768 | 38 |

Same build on LibAFL f8bb1882, other configs: zen2 `ryzen_zen2_desktop_parse_asp_flash`
34768 execs / 28 edges; zen1 `ryzen_zen1_desktop_parse_asp_flash` 127734 / 13;
`offchip_bhd_zen2_parse` 6981 / 562 (note: these runs predate the seed fix below).

## Campaign camp_secos_10190723
- config: `yaml/secos.yaml` (copy of the run's effective config in `camp_secos_10190723/config.yaml`)
- 3600 s, `-n 4`, 0 objectives, 756/756 edges
- command: `PROJECT_DIR=$PWD RUST_LOG=info aspfuzz -n 4 -y yaml/secos.yaml -r camp_secos_10190723`

## Known caveat
Before commit 'libasp: keep flash-extracted seed' the all-zero default input
overwrote the flash-extracted seed (`input0000`), so flash-base configs ran from
zeros. All numbers above were produced before that fix.
