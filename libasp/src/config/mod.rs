use libafl::inputs::UsesInput;
use libafl_bolts::tuples::{tuple_list, tuple_list_type};

pub mod tunnel;
use tunnel::TunnelConfig;

pub mod input;
use input::InputConfig;

pub mod crash;
use crash::{CrashConfig, CrashModule};

pub mod write_catcher;

use crate::reset_state::ResetLevel;
use crate::{ExceptionModule, LibAspModule};
/// Parsing the YAML config file
use libafl_qemu::*;
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
    pub fn get_last_off_chip_bl_instruction(&self) -> Vec<GuestAddr> {
        match self {
            ZenVersion::Zen2 => vec![0xffff24f8],
            _ => todo!(),
        }
    }

    /// This function returns a list of possible addresses that jumps into the on-chip BL
    /// This could be used in future work to update the `ExceptionHandler` address
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
    pub qemu: QemuConf,
    pub flash: FlashConfig,
    pub input: InputConfig,
    pub harness: HarnessConfig,
    pub tunnels: TunnelConfig,
    pub crashes: CrashConfig,
    pub snapshot: SnapshotConfig,
}

pub fn init_global_conf(config_path: &Path, num_cores: u32, run_dir: PathBuf) {
    let yaml = YAMLConfig::new(config_path);

    CONF.set(RunConfig {
        yaml_config: yaml,
        num_cores,
        run_dir,
        config_path: config_path.to_owned(),
    })
    .unwrap();
}

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
        S: UsesInput + Unpin,
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
        YAMLConfig::new(&d.join("../amd_sp/yaml/mailbox.yaml"));
    }
}
