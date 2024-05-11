use std::process;

use libafl::prelude::*;
use libafl_bolts::{os::unix_signals::Signal, prelude::*};
use libafl_qemu::{GuestAddr, Qemu, QemuExitReason, QemuExitReasonError, QemuShutdownCause, Regs};
use libasp::{get_run_conf, ExceptionType, Reset, ResetState};

use crate::client::ON_CHIP_ADDR;

extern "C" {
    fn aspfuzz_write_smn_flash(addr: GuestAddr, len: i32, buf: *mut u8);
}
pub unsafe fn write_flash_mem(addr: GuestAddr, buf: &[u8]) {
    aspfuzz_write_smn_flash(addr, buf.len() as i32, buf.as_ptr() as *mut u8);
}

pub fn create_harness(
    mut rs: ResetState,
    emu: Qemu,
) -> impl FnMut(&BytesInput) -> ExitKind + Clone {
    let mut is_crash_snapshot = false;
    let mut counter_snapshot = 0;
    move |input| {
        let conf = &get_run_conf().unwrap().yaml_config;
        log::debug!("### Start harness");

        // Reset emulator state
        if is_crash_snapshot {
            is_crash_snapshot = false;
            rs.load(&emu, &conf.snapshot_on_crash);
        } else if counter_snapshot >= conf.snapshot_period {
            counter_snapshot = 0;
            rs.load(&emu, &conf.snapshot_periodically);
        } else {
            rs.load(&emu, &conf.snapshot_default);
        }

        #[cfg(feature = "debug")]
        print_input(input.bytes());

        // Input to memory
        let target = input.target_bytes();
        let mut target_buf = target.as_slice();
        if target_buf.len() > conf.input_total_size {
            target_buf = &target_buf[..conf.input_total_size];
        }
        let mut buffer = vec![0; conf.input_total_size];
        buffer[..target_buf.len()].copy_from_slice(target_buf);
        let mut buffer = buffer.as_slice();
        let cpu = emu.current_cpu().unwrap(); // ctx switch safe
        for mem in conf.input_mem.iter() {
            unsafe {
                write_flash_mem(mem.0, &buffer[..mem.1]);
            }
            buffer = &buffer[mem.1..];
        }

        // Fixed values to memory
        for &(addr, value) in conf.input_fixed.iter() {
            let buffer = value.to_ne_bytes();
            unsafe {
                write_flash_mem(addr, &buffer);
            }
        }

        // Start the emulation
        let mut pc: u64 = cpu.read_reg(Regs::Pc).unwrap();
        log::debug!("Start at {:#x}", pc);
        unsafe {
            match emu.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(Signal::SigInterrupt))) => {
                    process::exit(CTRL_C_EXIT)
                }
                Err(QemuExitReasonError::UnexpectedExit) => return ExitKind::Crash,
                _ => panic!("Unexpected QEMU exit."),
            }
        };

        // After the emulator finished
        pc = cpu.read_reg(Regs::Pc).unwrap();
        let r0: u64 = cpu.read_reg(Regs::R0).unwrap();
        log::debug!("End at {:#x} with R0={:#x}", pc, r0);
        counter_snapshot += 1;
        // Look for crashes if no sink was hit
        if !conf.harness_sinks.iter().any(|&v| v == pc as GuestAddr) {
            // Don't trigger on exceptions
            if !(ON_CHIP_ADDR..(ON_CHIP_ADDR + 4 * ExceptionType::UNKNOWN as u32))
                .contains(&(pc as u32))
            {
                counter_snapshot = 0;
                is_crash_snapshot = true;

                log::info!("Found crash at {:#x}", pc);
                return ExitKind::Crash;
            }
        }
        log::debug!("End harness");
        ExitKind::Ok
    }
}

#[cfg(feature = "debug")]
fn print_input(input: &[u8]) {
    let mut out_str = "input=[\n".to_string();
    let mut iter = input.iter();
    let mut counter = 0;
    let mut last_byte = false;
    let mut last_no_print = false;
    loop {
        let mut word: [u8; 4] = [0; 4];
        for (i, word) in word.iter_mut().enumerate() {
            let obyte = iter.next();
            match obyte {
                Some(&byte) => *word = byte,
                None => {
                    last_byte = true;
                    if i == 0 {
                        last_no_print = true;
                    }
                    break;
                }
            }
        }
        if last_no_print {
            break;
        }
        unsafe {
            out_str.push_str(&format!(
                " {:08x},",
                std::mem::transmute::<[u8; 4], u32>(word)
            ));
        }
        counter += 1;
        if last_byte {
            break;
        }
        if counter % 4 == 0 {
            out_str.push('\n');
        }
    }
    out_str.push_str("\n]");

    log::info!("{}", out_str);
}
