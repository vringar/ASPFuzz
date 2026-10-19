/// Snapshot/reset levels from the yaml `snapshot:` section.
/// The custom reset machinery that used these levels was removed: the harness always uses the
/// built-in fast snapshot, so the levels are currently parsed but not acted on.
use std::fmt::{Debug, Formatter};
use std::str::FromStr;

use serde::Deserialize;

#[derive(Clone, Default, Deserialize)]
pub enum ResetLevel {
    /*
     *  Loading snapshot:
     *  - R0-R15, CPSR
     */
    SuperLazy,

    /*
     *  Loading snapshot:
     *  - R0-R15, CPSR
     *  - SRAM slice
     *      - Zen1 & Zen+ [0x3ED00, 0x40000]
     *      - Zen2 & Zen3 [0x4ED00, 0x50000]
     */
    #[default]
    Lazy,

    /*
     *  Loading snapshot:
     *  - R0-R15, CPSR
     *  - SRAM
     *      - Zen1 & Zen+ [0x0, 0x40000]
     *      - Zen2 & Zen3 [0x0, 0x50000]
     *  - Timer
     *  - SMN Control
     */
    RustSnapshot,

    /*
     * Qemu Native
     */
    QemuSnapshot,

    /*
     *  Resetting:
     *  - CPU
     *  - SRAM
     *      - Zen1 & Zen+ [0x0, 0x40000]
     *      - Zen2 & Zen3 [0x0, 0x50000]
     *  - Timer
     *  - SMN Control
     *  Executing until until harness entry
     */
    HardReset,
}

impl Debug for ResetLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut out_str = String::new();
        match *self {
            ResetLevel::SuperLazy => out_str.push_str("SuperLazy"),
            ResetLevel::Lazy => out_str.push_str("Lazy"),
            ResetLevel::RustSnapshot => out_str.push_str("RustSnapshot"),
            ResetLevel::QemuSnapshot => out_str.push_str("QemuSnapshot"),
            ResetLevel::HardReset => out_str.push_str("HardReset"),
        }
        write!(f, "{out_str}")
    }
}

impl FromStr for ResetLevel {
    type Err = ();
    fn from_str(input: &str) -> Result<ResetLevel, ()> {
        match input {
            "SuperLazy" => Ok(ResetLevel::SuperLazy),
            "Lazy" => Ok(ResetLevel::Lazy),
            "RustSnapshot" => Ok(ResetLevel::RustSnapshot),
            "QemuSnapshot" => Ok(ResetLevel::QemuSnapshot),
            "HardReset" => Ok(ResetLevel::HardReset),
            _ => Err(()),
        }
    }
}
