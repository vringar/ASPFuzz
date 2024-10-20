// Linux only
#![cfg(target_os = "linux")]

// Catching CPU exception during the execution
pub mod exception_handler;
pub use exception_handler::*;

// Generate metadata for each objective
pub mod gen_metadata;
pub use gen_metadata::*;

// Resetting the state aka. snapshotting in between fuzzing test-cases
pub mod reset_state;
use libafl_qemu::GuestAddr;
pub use reset_state::*;

pub mod emulator_module;
pub use emulator_module::*;

pub mod config;
pub mod memory;
pub use memory::*;

#[derive(Debug, Clone, Default)]
pub enum BootStage {
    #[default]
    OnChipBootloader,
    OffChipBootloader,
    TrustedOS,
}

impl BootStage {
    pub fn get_exception_vector_base(&self) -> GuestAddr {
        match self {
            BootStage::OnChipBootloader => 0x100,
            BootStage::OffChipBootloader => 0x100,
            BootStage::TrustedOS => 0x0,
        }
    }
}
