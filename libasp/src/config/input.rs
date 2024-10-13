use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl::Error;
use libafl_bolts::AsSlice;
use libafl_qemu::sys::GuestUsize;
/// Generate initial inputs for the fuzzer based on provided UEFI images
use libafl_qemu::{GuestAddr, Qemu, CPU};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Deserialize, Debug)]
pub struct InputLocation {
    addr: GuestAddr,
    size: usize,
}

#[derive(Clone, Deserialize, Debug)]
pub struct FixedLocation {
    addr: GuestAddr,
    val: GuestUsize,
}

/// In the `FlashConfig` all addrs are specified as their final address
/// in the PSP address space
/// This means that the position in the image can be determined by
/// `addr & 0x00FF_FFFF`
#[derive(Clone, Deserialize, Debug)]
pub struct FlashConfig {
    base: Vec<PathBuf>,
    #[serde(default)]
    input: Vec<InputLocation>,
    #[serde(default)]
    fixed: Vec<FixedLocation>,
}
impl FlashConfig {
    fn size(&self) -> usize {
        self.input.iter().fold(0, |counter, e| counter + e.size)
    }

    fn apply_input(&self, mut buffer: &[u8]) {
        for input_location in self.input.iter() {
            unsafe {
                write_flash_mem(input_location.addr, &buffer[..input_location.size]);
            }
            buffer = &buffer[input_location.size..];
        }

        // Fixed values to memory
        for &FixedLocation { addr, val } in self.fixed.iter() {
            let buffer = val.to_ne_bytes();
            unsafe {
                write_flash_mem(addr, &buffer);
            }
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct MemoryConfig {
    #[serde(default)]
    input: Vec<InputLocation>,
    #[serde(default)]
    fixed: Vec<FixedLocation>,
}
impl MemoryConfig {
    fn size(&self) -> usize {
        self.input.iter().fold(0, |counter, e| counter + e.size)
    }
    fn apply_input(&self, mut buf: &[u8], writer: impl Fn(GuestAddr, &[u8])) {
        for input_location in self.input.iter() {
            writer(input_location.addr, &buf[..input_location.size]);
            buf = &buf[input_location.size..];
        }

        // Fixed values to memory
        for &FixedLocation { addr, val } in self.fixed.iter() {
            let buffer = val.to_ne_bytes();
            writer(addr, &buffer);
        }
    }
}
/// Describes the entrirety of the fuzzable inputs
/// This includes the flash memory, x86 memory and psp memory
#[derive(Clone, Deserialize, Debug)]
pub struct InputConfig {
    #[serde(default)]
    flash: Option<FlashConfig>,
    #[serde(default)]
    x86: Option<MemoryConfig>,
    #[serde(default)]
    psp: Option<MemoryConfig>,
}

impl InputConfig {
    pub fn total_size(&self) -> usize {
        self.flash.as_ref().map(|i| i.size()).unwrap_or(0)
            + self.x86.as_ref().map(|i| i.size()).unwrap_or(0)
            + self.psp.as_ref().map(|i| i.size()).unwrap_or(0)
    }
}

impl InputConfig {
    pub fn create_initial_inputs(&self, flash_size: GuestAddr, input_dir: &PathBuf) {
        let input_total_size = self.total_size();

        if let Some(flash) = &self.flash {
            if !flash.base.is_empty() {
                for (i, base) in flash.base.iter().enumerate() {
                    let mut new_input_image = Vec::<u8>::new();
                    assert!(base.exists());
                    let image: Vec<u8> = fs::read(base).unwrap();
                    // We're copying the input locations and appending them
                    // to the initial input. This ensures we are mutating from a known good state
                    for mem in flash.input.iter() {
                        assert!(
                            mem.addr < flash_size && (mem.size as GuestAddr) < flash_size,
                            "Memory region outsize of flash memory size"
                        );
                        let mem_section = &image[((mem.addr & 0x00FF_FFFF) as usize)
                            ..((mem.addr & 0x00FF_FFFF) as usize) + mem.size];
                        new_input_image.extend_from_slice(mem_section);
                    }
                    if input_total_size != new_input_image.len() {
                        panic!("Extracted input to short");
                    }
                    let mut new_input_path = PathBuf::from(&input_dir);
                    new_input_path.push(format!("input{:#04}", i));
                    fs::write(new_input_path, new_input_image).unwrap();
                }
            }
            return;
        }

        let mut new_input_path = PathBuf::from(&input_dir);
        new_input_path.push("input0000");
        fs::write(new_input_path, vec![0; input_total_size]).unwrap();
    }

    pub fn apply_input(&self, input: &BytesInput) {
        // Input to memory
        let target = input.target_bytes();
        let mut target_buf = target.as_slice();

        if let Some(flash) = self.flash.as_ref() {
            let flash_buf = &target_buf[..flash.size()];
            target_buf = &target_buf[flash.size()..];
            flash.apply_input(flash_buf);
        }
        let qemu = Qemu::get().unwrap();
        let cpu = &qemu.cpu_from_index(0);

        if let Some(x86) = self.x86.as_ref() {
            let x86_buf = &target_buf[..x86.size()];
            target_buf = &target_buf[x86.size()..];
            x86.apply_input(x86_buf, |addr, buf| {
                write_x86_mem(cpu, addr, buf).expect("Failed to write to memory")
            });
        }

        if let Some(psp) = self.psp.as_ref() {
            let x86_buf = &target_buf[..psp.size()];
            target_buf = &target_buf[psp.size()..];
            psp.apply_input(x86_buf, |addr, buf| unsafe { cpu.write_mem(addr, buf) });
        }

        assert!(target_buf.is_empty());
    }
}

extern "C" {
    fn aspfuzz_write_smn_flash(addr: GuestAddr, len: i32, buf: *mut u8);
    fn aspfuzz_x86_write(addr: GuestAddr, buf: *mut u8, len: i32) -> i32;
}
/// # Safety
/// This function should only be called if QEMU has been fully initialized
/// and the flash memory is accessible
pub unsafe fn write_flash_mem(addr: GuestAddr, buf: &[u8]) {
    aspfuzz_write_smn_flash(addr, buf.len() as i32, buf.as_ptr() as *mut u8);
}
/// Provide the CPU as proof that QEMU has been initialized and is halted
pub fn write_x86_mem(_cpu: &CPU, addr: GuestAddr, buf: &[u8]) -> Result<(), Error> {
    let i;
    unsafe {
        i = aspfuzz_x86_write(addr, buf.as_ptr() as *mut u8, buf.len() as i32);
    }
    if i == 0 {
        Ok(())
    } else {
        Err(Error::illegal_state("Failed to write to x86 memory"))
    }
}
