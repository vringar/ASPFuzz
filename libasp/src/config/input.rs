use byteorder::{LittleEndian, ReadBytesExt};
use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl_bolts::AsSlice;
use libafl_qemu::sys::GuestUsize;
/// Generate initial inputs for the fuzzer based on provided UEFI images
use libafl_qemu::{GuestAddr, GuestPhysAddr, Qemu};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::{fs, vec};

use crate::config::get_run_conf;
use crate::{write_flash_mem, write_mailbox_value, write_x86_mem, MailboxValues};

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
        for input_location in &self.input {
            unsafe {
                write_flash_mem(input_location.addr, &buffer[..input_location.size]);
            }
            buffer = &buffer[input_location.size..];
        }

        // Fixed values to memory
        for &FixedLocation { addr, val } in &self.fixed {
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
        for input_location in &self.input {
            log::debug!(
                "Writing input to memory: {:#x} size: {} value: {:02x?}",
                input_location.addr,
                input_location.size,
                &buf[..input_location.size]
            );
            writer(input_location.addr, &buf[..input_location.size]);
            buf = &buf[input_location.size..];
        }

        // Fixed values to memory
        for &FixedLocation { addr, val } in &self.fixed {
            log::debug!("Writing constant at {addr:#x} value: {val}");
            let buffer = val.to_ne_bytes();
            writer(addr, &buffer);
        }
    }
}

/// used if mailbox_content: true to determine location in x86 space and size there
#[derive(Clone, Deserialize, Debug)]
pub struct MailboxConfig {
    mbox_high: GuestAddr,
    mbox_low: GuestAddr,
    size: usize,
}

impl MailboxConfig {
    fn size(&self) -> usize {self.size}
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
    #[serde(default)]
    mailbox: Option<bool>,
    mailbox_config: Option<MailboxConfig>,
    initial_inputs: Option<Vec<PathBuf>>,
}

impl InputConfig {
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.flash.as_ref().map_or(0, FlashConfig::size)
            + self.x86.as_ref().map_or(0, MemoryConfig::size)
            + self.psp.as_ref().map_or(0, MemoryConfig::size)
            + if self.has_mailbox() {
                // 8 for high+low or size for content, + 4 for command-register
                self.mailbox_config.as_ref().map_or(8, MailboxConfig::size) + 4
            } else { 0 }
    }
}

impl InputConfig {
    pub fn create_initial_inputs(&self, flash_size: GuestAddr, input_dir: &Path) {
        let input_total_size = self.total_size();

        if let Some(flash) = &self.flash {
            if !flash.base.is_empty() {
                for (i, base) in flash.base.iter().enumerate() {
                    let mut new_input_image = Vec::<u8>::new();
                    assert!(base.exists());
                    let image: Vec<u8> = fs::read(base).unwrap();
                    // We're copying the input locations and appending them
                    // to the initial input. This ensures we are mutating from a known good state
                    for mem in &flash.input {
                        assert!(
                            mem.addr < flash_size && (mem.size as GuestAddr) < flash_size,
                            "Memory region outsize of flash memory size"
                        );
                        let mem_section = &image[((mem.addr & 0x00FF_FFFF) as usize)
                            ..((mem.addr & 0x00FF_FFFF) as usize) + mem.size];
                        new_input_image.extend_from_slice(mem_section);
                    }
                    assert!(
                        (input_total_size == new_input_image.len()),
                        "Extracted input to short"
                    );
                    let mut new_input_path = PathBuf::from(&input_dir);
                    new_input_path.push(format!("input{i:#04}"));
                    fs::write(new_input_path, new_input_image).unwrap();
                }
            }
        }
        self.setup_input_dir(input_dir);
        // Create a default input if there are no inputs or all other inputs are wins
        let mut new_input_path = PathBuf::from(&input_dir);
        new_input_path.push("input0000");
        fs::write(new_input_path, vec![0_u8; input_total_size]).unwrap();
        log::info!("Input Size is {}", self.total_size());
    }

    #[must_use]
    pub fn setup_input_dir(&self, target_dir: &Path) -> Option<()> {
        let Some(inputs) = &self.initial_inputs else {
            return None;
        };
        let mut counter = 0;
        for input in inputs {
            if input.is_dir() {
                let Ok(read_dir) = fs::read_dir(input) else {
                    log::error!("Failed to read directory {}", input.display());
                    continue;
                };
                for entry in read_dir {
                    let Ok(entry) = entry else {
                        log::error!("Failed to read entry in directory {}", input.display());
                        continue;
                    };
                    let entry_path = entry.path();
                    fs::copy(
                        &entry_path,
                        target_dir.join(entry_path.file_name().unwrap()),
                    )
                    .unwrap();
                    counter += 1;
                }
            } else {
                log::error!("Input path is not a directory {}", input.display());
                let path = target_dir.join(input.file_name().unwrap());
                let Ok(_) = fs::copy(input, path) else {
                    log::error!("Failed to copy input file {}", input.display());
                    continue;
                };
                counter += 1;
            }
        }
        log::debug!(
            "Copied {} initial inputs to {}",
            counter,
            target_dir.display()
        );
        if counter == 0 {
            None
        } else {
            Some(())
        }
    }
    pub fn apply_input(&self, input: &BytesInput) {
        // Input to memory
        let target = input.target_bytes();
        let input_bytes = target.as_slice();
        if get_run_conf().unwrap().yaml_config.debug {
            log::info!(
                "Input bytes length: {} value: {:02x?}",
                input_bytes.len(),
                input_bytes
            );
        }
        let mut tmp_vec = Vec::from(input_bytes);
        tmp_vec.resize(self.total_size(), 0); // TODO: allow for variable length maybe
        let mut target_buf = tmp_vec.as_slice();
        if let Some(flash) = self.flash.as_ref() {
            let flash_buf = &target_buf[..flash.size()];
            target_buf = &target_buf[flash.size()..];
            flash.apply_input(flash_buf);
        }
        let qemu = Qemu::get().unwrap();
        let cpu = &qemu.cpu_from_index(0).expect("We always have one CPU");

        if let Some(x86) = self.x86.as_ref() {
            let x86_buf = &target_buf[..x86.size()];
            target_buf = &target_buf[x86.size()..];
            x86.apply_input(x86_buf, |addr, buf| {
                write_x86_mem(cpu, addr.into(), buf).expect("Failed to write to memory");
            });
        }

        if let Some(psp) = self.psp.as_ref() {
            let psp_buf = &target_buf[..psp.size()];
            target_buf = &target_buf[psp.size()..];
            psp.apply_input(psp_buf, |addr, buf| {
                cpu.write_mem(addr, buf).expect("Input writing failed");
            });
        }
        if let Some(true) = self.mailbox {
            let lower : u32;
            let higher: u32;
            if let Some(content) = self.mailbox_config.as_ref() {
                log::info!("Mailbox content: {:?}", content);
                lower = content.mbox_low;
                higher = content.mbox_high;
            } else {
                lower = target_buf
                    .read_u32::<LittleEndian>()
                    .expect("Not enough bytes for ptr_lower");
                higher = (target_buf
                    .read_u32::<LittleEndian>()
                    .expect("Not enough bytes for ptr_higher")
                    | 0x0000_fffc)
                    & 0x0000_ffff;
            }
            
            write_mailbox_value(
                cpu,
                MailboxValues {
                    mbox: target_buf
                        .read_u32::<LittleEndian>()
                        .expect("Not enough bytes for mailbox"),
                    ptr_lower: lower,
                    ptr_higher: higher,
                },
            )
            .expect("Failed to write to mailbox");

            if let Some(content) = self.mailbox_config.as_ref() {
                let x86_buf = &target_buf[..content.size];
                target_buf = &target_buf[content.size..];
                write_x86_mem(cpu, ((content.mbox_high as GuestPhysAddr) << 32 + (content.mbox_low as GuestPhysAddr)).into(), &x86_buf).expect("Failed to write to memory");
            }
        }
        qemu.flush_jit();
        assert!(target_buf.is_empty());
    }

    #[must_use]
    pub fn has_mailbox(&self) -> bool {
        self.mailbox.unwrap_or(false)
    }
}
