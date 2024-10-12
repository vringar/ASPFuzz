//mod client;
#[cfg(all(target_os = "linux", not(feature = "performance")))]
mod fuzzer;
mod harness;
#[cfg(all(target_os = "linux", feature = "performance"))]
mod performance;
mod setup;

use libafl::Error;

#[cfg(target_os = "linux")]
pub fn main() -> Result<(), Error> {
    #[cfg(not(feature = "performance"))]
    return fuzzer::fuzz();
    #[cfg(feature = "performance")]
    performance::fuzz();
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-system and libafl_qemu is only supported on linux!");
}
