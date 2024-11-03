//mod client;
#[cfg(target_os = "linux")]
mod fuzzer;
mod setup;

use libafl::Error;

#[cfg(target_os = "linux")]
pub fn main() -> Result<(), Error> {
    fuzzer::fuzz()
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-system and libafl_qemu is only supported on linux!");
}
