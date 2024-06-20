use crate::reset_state::ResetLevel;
use crate::TunnelConfig;
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

#[derive(Deserialize, Debug)]
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
}

#[derive(Deserialize, Debug)]
pub struct QemuConf {
    pub zen: ZenVersion,
    pub on_chip_bl_path: PathBuf,
}
#[derive(Deserialize, Debug)]
pub struct FlashConfig {
    pub start_smn: GuestAddr,
    pub size: GuestUsize,
    pub start_cpu: GuestAddr,
    pub base: PathBuf,
}

#[derive(Deserialize, Debug)]
pub struct MemConfig {
    pub addr: GuestAddr,
    pub size: usize,
}

#[derive(Deserialize, Debug)]
pub struct FixedConfig {
    pub addr: GuestAddr,
    pub val: GuestUsize,
}
#[derive(Deserialize, Debug)]
pub struct InputConfig {
    pub initial: Vec<PathBuf>,
    pub mem: Vec<MemConfig>,
    pub fixed: Vec<FixedConfig>,
}

impl InputConfig {
    pub fn total_size(&self) -> usize {
        self.mem.iter().fold(0, |counter, e| counter + e.size)
    }
}

#[derive(Deserialize, Debug)]
pub struct HarnessConfig {
    pub start: GuestAddr,
    pub sinks: Vec<GuestAddr>,
}
#[derive(Deserialize, Debug)]
pub struct NoExecConfig {
    pub begin: GuestAddr,
    pub end: GuestAddr,
}

#[derive(Deserialize, Debug)]
pub struct RegionWithHoles {
    pub begin: GuestAddr,
    pub end: GuestAddr,
    #[serde(default)]
    pub holes: Vec<GuestAddr>,
}

#[derive(Deserialize, Debug)]
pub struct CrashConfig {
    pub breakpoints: Vec<GuestAddr>,
    pub mmap: MmapConfig,
}

#[derive(Deserialize, Debug)]
pub struct MmapConfig {
    pub no_exec: Vec<NoExecConfig>,
    pub flash_read_fn: GuestAddr,
    pub no_write_flash_fn: Vec<RegionWithHoles>,
    pub no_write_hooks: Vec<RegionWithHoles>,
}

#[derive(Deserialize, Debug)]
pub struct SnapshotConfig {
    pub default: ResetLevel,
    pub on_crash: ResetLevel,
    pub periodically: ResetLevel,
    pub period: usize,
}

#[derive(Deserialize, Debug)]
pub struct YAMLConfig {
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
        YAMLConfig::new(&d.join("../amd_sp/yaml/ryzen_zen2_desktop_offchip_mailbox.yaml"));
    }
}
