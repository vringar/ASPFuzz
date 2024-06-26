/// Generate initial inputs for the fuzzer based on provided UEFI images
use libafl_qemu::GuestAddr;
use std::fs;
use std::path::PathBuf;

use crate::MemConfig;

pub struct InitialInput {}

impl Default for InitialInput {
    fn default() -> Self {
        Self::new()
    }
}

impl InitialInput {
    pub fn new() -> Self {
        Self {}
    }

    pub fn create_initial_inputs(
        &self,
        flash_base: &[PathBuf],
        input_mem: &[MemConfig],
        flash_size: GuestAddr,
        input_total_size: usize,
        input_dir: PathBuf,
    ) -> PathBuf {
        if flash_base.is_empty() {
            let mut new_input_path = PathBuf::from(&input_dir);
            new_input_path.push("input0000");
            fs::write(new_input_path, vec![0; input_total_size]).unwrap();
        }
        for (i, base) in flash_base.iter().enumerate() {
            let mut new_input_image = Vec::<u8>::new();
            assert!(base.exists());
            let image: Vec<u8> = fs::read(base).unwrap();
            for mem in input_mem.iter() {
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
        input_dir
    }
}
