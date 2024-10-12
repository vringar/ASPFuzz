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
pub use reset_state::*;

pub mod emulator_module;
pub use emulator_module::*;

pub mod config;
