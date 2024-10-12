use std::process;

use libafl::prelude::*;
use libafl_bolts::{os::unix_signals::Signal, prelude::*};
use libafl_qemu::{
    command::CommandManager, Emulator, QemuExitError, QemuExitReason, QemuShutdownCause, Regs,
};
use libasp::config::get_run_conf;

pub type MyState =
    StdState<BytesInput, InMemoryCorpus<BytesInput>, RomuDuoJrRand, OnDiskCorpus<BytesInput>>;

pub fn _create_harness<CM, ED, ET, SM>(
) -> impl FnMut(Emulator<CM, ED, ET, MyState, SM>, MyState, &BytesInput) -> ExitKind + Clone
where
    CM: CommandManager<ED, ET, MyState, SM>,
{
    move |emulator: Emulator<CM, ED, ET, MyState, SM>, _state, input| {
        let conf = &get_run_conf().unwrap().yaml_config;
        log::debug!("### Start harness");
        // TODO: emulator.restore_fast_snapshot(snapshot)
        #[cfg(feature = "debug")]
        print_input(input.bytes());
        let cpu = emulator.qemu().current_cpu().unwrap(); // ctx switch safe
        conf.input.apply_input(input);

        // Start the emulation
        let mut pc: u32 = cpu.read_reg(Regs::Pc).unwrap();
        log::debug!("Start at {:#x}", pc);
        unsafe {
            match emulator.qemu().run() {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(Signal::SigInterrupt))) => {
                    process::exit(CTRL_C_EXIT)
                }
                Err(QemuExitError::UnexpectedExit) => {
                    log::error!(
                        "Got unexpected crash at {:#x}",
                        cpu.read_reg::<_, u32>(Regs::Pc).unwrap()
                    );
                    return ExitKind::Crash;
                }
                _ => panic!("Unexpected QEMU exit."),
            }
        };

        // After the emulator finished
        pc = cpu.read_reg(Regs::Pc).unwrap();
        let r0: u64 = cpu.read_reg(Regs::R0).unwrap();
        log::debug!("End at {:#x} with R0={:#x}", pc, r0);
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
