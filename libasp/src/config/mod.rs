use libafl_bolts::tuples::{tuple_list, tuple_list_type};

pub mod tunnel;
use tunnel::TunnelConfig;

pub mod input;
use input::InputConfig;

pub mod crash;
use crash::{CrashConfig, CrashModule};

pub mod access_observer;

use crate::reset_state::ResetLevel;
use crate::{ExceptionModule, LibAspModule};
/// Parsing the YAML config file
use libafl_qemu::{sys, GuestAddr};
use serde::Deserialize;
use sys::GuestUsize;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static CONF: OnceLock<RunConfig> = OnceLock::new();

#[derive(Debug)]
pub struct RunConfig {
    pub yaml_config: YAMLConfig,
    pub num_cores: u32,
    pub run_dir: PathBuf,
    pub config_path: PathBuf,
    /// Diagnostic: verify the fuzz-iteration snapshot restore is deterministic
    /// via `check_fast_snapshot` (board #334/#354). Off unless `--verify-reset`.
    pub verify_reset: bool,
    /// Device to isolate in the verify-reset snapshot (`--verify-reset-device`).
    pub verify_reset_device: Option<String>,
}

#[derive(Clone, Deserialize, Debug)]
pub enum ZenVersion {
    Zen1,
    #[serde(alias = "Zen+")]
    ZenPlus,
    Zen2,
    Zen3,
    Zen4,
    ZenTesla,
}

impl ZenVersion {
    #[must_use]
    pub fn get_qemu_machine_name(&self) -> &'static str {
        match self {
            ZenVersion::Zen1 => "amd-psp-zen",
            ZenVersion::ZenPlus => "amd-psp-zen+",
            ZenVersion::Zen2 => "amd-psp-zen2",
            ZenVersion::Zen3 => "amd-psp-zen3",
            ZenVersion::Zen4 => panic!("Zen4 is currently not supported"),
            ZenVersion::ZenTesla => "amd-psp-zentesla",
        }
    }
    /// This function returns a list of possible addresses that jumps into the on-chip BL
    /// This could be used in future work to update the `ExceptionHandler` address
    #[must_use]
    pub fn get_last_off_chip_bl_instruction(&self) -> Vec<GuestAddr> {
        match self {
            ZenVersion::Zen2 => vec![0xffff24f8],
            _ => todo!(),
        }
    }

    /// This function returns a list of possible addresses that jumps into the on-chip BL
    /// This could be used in future work to update the `ExceptionHandler` address
    #[must_use]
    pub fn get_last_on_chip_bl_instruction(&self) -> Vec<GuestAddr> {
        match self {
            ZenVersion::Zen2 => vec![0x450],
            _ => todo!(),
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct QemuConf {
    pub zen: ZenVersion,
    pub on_chip_bl_path: PathBuf,
}
#[derive(Clone, Deserialize, Debug)]
pub struct FlashConfig {
    pub size: GuestUsize,
    pub base: PathBuf,
}

#[derive(Clone, Deserialize, Debug)]
pub struct HarnessConfig {
    pub start: GuestAddr,
    pub sinks: Vec<GuestAddr>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct RegionWithHoles {
    pub begin: GuestAddr,
    pub end: GuestAddr,
    #[serde(default)]
    pub holes: Vec<GuestAddr>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct SnapshotConfig {
    pub default: ResetLevel,
    pub on_crash: ResetLevel,
    pub periodically: ResetLevel,
    pub period: usize,
}

#[derive(Clone, Deserialize, Debug)]
pub struct YAMLConfig {
    #[serde(default)]
    pub debug: bool,
    /// Use only mutators that keep the input length (no insert/delete/expand)
    #[serde(default)]
    pub fixed_length_mutators: bool,
    /// Add field-aware mailbox mutators (command id, framing, argument dwords); needs `input.mailbox_config`
    #[serde(default)]
    pub structured_mailbox: bool,
    /// Comparison-feedback guided mutation (CmpLog + input-to-state replacement) for the
    /// `structured_mailbox` flat-bytes path. Off by default.
    #[serde(default)]
    pub cmplog: bool,
    /// Per-iteration timeout in milliseconds (default 10000). A hung iteration (e.g. SecOS command 0x40
    /// waits forever) costs this much wall time each, so lower it for harnesses whose iterations take ms.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Mailbox value dictionary (see `amd_sp/tools/gen_mailbox_dict.py`); used by the structured mailbox mutator
    #[serde(default)]
    pub mailbox_dict: Option<PathBuf>,
    /// Command ids the mailbox mutators never pick (e.g. [0x40]: waits forever and costs a full timeout)
    #[serde(default)]
    pub mailbox_skip_cmds: Vec<u32>,
    /// One input is a SESSION of typed mailbox messages replayed within one snapshot restore (see
    /// `amd_sp/src/structured`); needs `mailbox_catalog` and `input.mailbox_config`. Off by default.
    #[serde(default)]
    pub structured_session: bool,
    /// Protocol catalog JSON (local-only, never committed) driving the session mutators
    #[serde(default)]
    pub mailbox_catalog: Option<PathBuf>,
    /// Maximum messages per session (default 6); the per-session time budget is `timeout_ms`
    #[serde(default)]
    pub session_len: Option<usize>,
    pub qemu: QemuConf,
    pub flash: FlashConfig,
    pub input: InputConfig,
    pub harness: HarnessConfig,
    pub tunnels: TunnelConfig,
    pub crashes: CrashConfig,
    pub snapshot: SnapshotConfig,
}

pub fn init_global_conf(
    config_path: &Path,
    num_cores: u32,
    run_dir: PathBuf,
    verify_reset: bool,
    verify_reset_device: Option<String>,
) {
    let yaml = YAMLConfig::new(config_path);
    log::warn!(
        "snapshot.default/on_crash/periodically ({:?}/{:?}/{:?}) are parsed but ignored: the fast snapshot is always used",
        yaml.snapshot.default,
        yaml.snapshot.on_crash,
        yaml.snapshot.periodically
    );

    CONF.set(RunConfig {
        yaml_config: yaml,
        num_cores,
        run_dir,
        config_path: config_path.to_owned(),
        verify_reset,
        verify_reset_device,
    })
    .unwrap();
}

#[must_use]
pub fn borrow_global_conf() -> Option<&'static YAMLConfig> {
    get_run_conf().map(|e| &e.yaml_config)
}
pub fn get_run_conf() -> Option<&'static RunConfig> {
    CONF.get()
}
impl YAMLConfig {
    fn new(config_file: &Path) -> Self {
        let file = File::options()
            .read(true)
            .write(false)
            .open(config_file)
            .expect("Unable to open yaml config file");

        serde_yaml::from_reader(file).unwrap()
    }
    pub fn get_emulator_modules<S>(
        &self,
    ) -> tuple_list_type!(LibAspModule, CrashModule, ExceptionModule)
    where
        S: Unpin,
    {
        tuple_list!(
            LibAspModule::new(self.clone()),
            CrashModule::new(self.crashes.clone()),
            ExceptionModule::new(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    #[test]
    fn read_zen1() {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        println!("CARGO PATH IS {}", d.display());
        YAMLConfig::new(&d.join("../amd_sp/yaml/ryzen_zen1_desktop_parse_asp_flash.yaml"));
    }

    #[test]
    fn read_zen2() {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        println!("CARGO PATH IS {}", d.display());
        YAMLConfig::new(&d.join("../amd_sp/yaml/ryzen_zen2_desktop_parse_asp_flash.yaml"));
    }
    #[test]
    fn read_zen3() {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        println!("CARGO PATH IS {}", d.display());
        YAMLConfig::new(&d.join("../amd_sp/yaml/ryzen_zen3_desktop_parse_asp_flash.yaml"));
    }
    #[test]
    fn read_zentesla() {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        println!("CARGO PATH IS {}", d.display());
        YAMLConfig::new(&d.join("../amd_sp/yaml/ryzen_zentesla_parse_asp_flash.yaml"));
    }
    #[test]
    fn read_zenplus() {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        println!("CARGO PATH IS {}", d.display());
        YAMLConfig::new(&d.join("../amd_sp/yaml/ryzen_zen+_desktop_parse_asp_flash.yaml"));
    }

    #[test]
    fn read_mailbox() {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        println!("CARGO PATH IS {}", d.display());
        YAMLConfig::new(&d.join("../amd_sp/yaml/mailbox_zen2_experimental.yaml"));
    }
}
