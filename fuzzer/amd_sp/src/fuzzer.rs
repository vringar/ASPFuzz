use libafl::prelude::*;
use libafl_bolts::core_affinity::Cores;
use libafl_bolts::current_nanos;
use libafl_bolts::current_time;
use libafl_bolts::rands::StdRand;
use libafl_bolts::shmem::ShMemProvider;
use libafl_bolts::shmem::StdShMemProvider;
use libafl_bolts::tuples::tuple_list;
use libafl_bolts::AsSlice;
use libafl_qemu::drcov::QemuDrCovHelper;
use libafl_qemu::edges::edges_map_mut_slice;
use libafl_qemu::edges::MAX_EDGES_NUM;
use libafl_qemu::sys::TCGTemp;
use libafl_qemu::*;

use libasp::*;

use rangemap::RangeMap;

use nix::{self, unistd::dup};
use std::cell::RefCell;
use std::env;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::ptr::addr_of_mut;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::setup::parse_args;

const ON_CHIP_ADDR: GuestAddr = 0xffff_0000;

static mut COUNTER_EDGE_HOOKS: usize = 0;
static COUNTER_WRITE_HOOKS: AtomicU64 = AtomicU64::new(0);
static mut COUNTER_SNAPSHOT: usize = 0;
static mut CRASH_SNAPSHOT: bool = false;
static mut FLASH_READ_HOOK_ID: usize = 0;

fn gen_block_hook<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _id: Option<&mut S>,
    src: GuestAddr,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let conf = borrow_global_conf().unwrap();
    for no_exec in conf.crashes_mmap_no_exec.iter() {
        if src >= no_exec[0] && src < no_exec[1] {
            log::debug!("Generate block:");
            log::debug!("> src: {:#x}", src);
            unsafe { COUNTER_EDGE_HOOKS += 1 };
            log::debug!("> id: {:#x}", unsafe { COUNTER_EDGE_HOOKS });
            hooks.qemu().current_cpu().unwrap().trigger_breakpoint();
            return Some(unsafe { COUNTER_EDGE_HOOKS } as u64);
        }
    }
    if !conf.crashes_mmap_no_write_flash_fn.is_empty() && conf.crashes_mmap_flash_read_fn == src {
        log::debug!("Adding block hook for flash_read_fn");
        unsafe {
            COUNTER_EDGE_HOOKS += 1;
            FLASH_READ_HOOK_ID = COUNTER_EDGE_HOOKS;
        }
        return Some(unsafe { COUNTER_EDGE_HOOKS } as u64);
    }
    None
}

fn exec_block_hook<QT, S>(hooks: &mut QemuHooks<QT, S>, _data_maybe: Option<&mut S>, id: u64)
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emu = hooks.qemu();
    if unsafe { FLASH_READ_HOOK_ID } == id as usize {
        let conf = borrow_global_conf().unwrap();
        let cpu = emu.current_cpu().unwrap();
        let pc: u64 = cpu.read_reg(Regs::Pc).unwrap();
        log::debug!("Flash read fn id was hit");
        if pc as GuestAddr == conf.crashes_mmap_flash_read_fn {
            let cpy_src: GuestAddr =
                cpu.read_reg::<libafl_qemu::Regs, u64>(Regs::R0).unwrap() as GuestAddr;
            let cpy_dest_start: GuestAddr =
                cpu.read_reg::<libafl_qemu::Regs, u64>(Regs::R1).unwrap() as GuestAddr;
            let cpy_len: GuestAddr =
                cpu.read_reg::<libafl_qemu::Regs, u64>(Regs::R2).unwrap() as GuestAddr;
            let cpy_dest_end: GuestAddr = cpy_dest_start + cpy_len;
            log::debug!(
                "Flash read fn from {:#010x} to {:#010x} for {:#x} bytes",
                cpy_src,
                cpy_dest_start,
                cpy_len
            );
            for area in &conf.crashes_mmap_no_write_flash_fn {
                if (area.0 >= cpy_dest_start && area.0 < cpy_dest_end)
                    || (area.1 >= cpy_dest_start && area.1 < cpy_dest_end)
                {
                    log::debug!(
                        "Flash read fn writes to [{:#010x}, {:#010x}]",
                        area.0,
                        area.1
                    );
                    let cpy_lr: GuestAddr =
                        cpu.read_reg::<libafl_qemu::Regs, u64>(Regs::Lr).unwrap() as GuestAddr;
                    log::debug!("Flash read fn called from {:#010x}", cpy_lr);
                    if !area.2.contains(&cpy_lr) {
                        log::info!("Flash read fn hook triggered!");
                        cpu.trigger_breakpoint();
                    }
                }
            }
        }
        return;
    }
    log::debug!("Execute block:");
    log::debug!("> id: {}", id);
    // log::debug!("> data: {}", (todo!() as u32));
    emu.current_cpu().unwrap().trigger_breakpoint();
}

fn gen_writes_hook<QT, S>(
    _hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    _: *mut TCGTemp,
    mem_acces_info: MemAccessInfo,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    // TODO: for known write locations at "compile" time
    // Don't emit hooks if they are outside of range
    let conf = borrow_global_conf().unwrap();
    for (_, _, no_write) in conf.crashes_mmap_no_write_hooks.iter() {
        for no_ldr in no_write {
            if pc == *no_ldr {
                log::debug!("Skipping generation hook for {:#010x}", pc);
                return None;
            }
        }
    }
    let size = mem_acces_info.size();
    log::debug!("Generate writes:");
    log::debug!("> src: {:#x}", pc);
    log::debug!("> size: {}", size);
    let hook_id = COUNTER_WRITE_HOOKS.fetch_add(1, Ordering::SeqCst);
    log::debug!("> id: {:#x}", hook_id);
    Some(hook_id)
}

fn exec_writes_hook<QT: QemuHelperTuple<S>, S: UsesInput>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    id: u64,
    addr: GuestAddr,
) {
    let conf = borrow_global_conf().unwrap();
    for &(lower_bound, upper_bound, _) in conf.crashes_mmap_no_write_hooks.iter() {
        if addr >= lower_bound && addr < upper_bound {
            log::debug!("Execute writes:");
            log::debug!("> id: {:#x}", id);
            log::debug!("> addr: {:#x}", addr);
            // log::debug!("> data: {}", todo!() as u64);
            let emu = hooks.qemu();
            emu.current_cpu().unwrap().trigger_breakpoint();
        }
    }
}
fn exec_writes_hook_n<QT: QemuHelperTuple<S>, S: UsesInput>(
    hooks: &mut QemuHooks<QT, S>,
    _input: Option<&mut S>,
    id: u64,
    addr: u32,
    size: usize,
) {
    let conf = borrow_global_conf().unwrap();
    for no_write in conf.crashes_mmap_no_write_hooks.iter() {
        if addr >= no_write.0 && addr < no_write.1 {
            log::debug!("Execute writes:");
            log::debug!("> id: {:#x}", id);
            log::debug!("> addr: {:#x}", addr);
            log::debug!("> size: {}", size);
            // log::debug!("> data: {}", (todo!() as u32));
            hooks.qemu().current_cpu().unwrap().trigger_breakpoint();
        }
    }
}

extern "C" {
    fn aspfuzz_write_smn_flash(addr: GuestAddr, len: i32, buf: *mut u8);
}
pub unsafe fn write_flash_mem(addr: GuestAddr, buf: &[u8]) {
    aspfuzz_write_smn_flash(addr, buf.len() as i32, buf.as_ptr() as *mut u8);
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

fn run(qemu_args: Vec<String>) {
    let env: Vec<(String, String)> = env::vars().collect();

    let emu = Qemu::init(&qemu_args, &env).unwrap();
    let conf = borrow_global_conf().unwrap();

    // Create directory for this run
    let run_dir = &get_run_conf().unwrap().run_dir;
    if env::var("AFL_LAUNCHER_CLIENT").is_err() && run_dir.exists() {
        fs::remove_dir_all(run_dir).unwrap();
    }
    fs::create_dir_all(run_dir).unwrap();
    let mut input_dir = run_dir.clone();
    input_dir.push("inputs");
    fs::create_dir_all(&input_dir).unwrap();
    let mut log_dir = run_dir.clone();
    log_dir.push("logs");
    fs::create_dir_all(&log_dir).unwrap();
    let mut solutions_dir = run_dir.clone();
    solutions_dir.push("solutions");
    fs::create_dir_all(&solutions_dir).unwrap();
    let mut config_path = run_dir.clone();
    config_path.push("config.yaml");
    if env::var("AFL_LAUNCHER_CLIENT").is_err() {
        fs::copy(&conf.config_file, &config_path).unwrap();
    }

    // Generate initial inputs
    let input_dir: PathBuf = InitialInput::new().create_initial_inputs(
        &conf.input_initial,
        &conf.input_mem,
        conf.flash_size as GuestAddr,
        conf.input_total_size,
        input_dir,
    );

    // Configure ResetState and ExceptionHandler helpers
    let mut rs = ResetState::new(conf.qemu_sram_size);
    let mut eh = ExceptionHandler::new(ON_CHIP_ADDR);

    // Set fuzzing sinks
    for sink in &conf.harness_sinks {
        emu.set_breakpoint(*sink);
    }

    // Go to FUZZ_START
    let addr = conf.harness_start;
    emu.set_breakpoint(addr);
    unsafe {
        match emu.run() {
            Ok(QemuExitReason::Breakpoint(guest_addr)) => { assert_eq!(guest_addr,conf.harness_start); println!("Guest addr: {guest_addr}, Conf harness: {addr}")}
            _ => panic!("Unexpected QEMU exit."),
        }
    };
    emu.remove_breakpoint(conf.harness_start);
    let mut cpu = emu.current_cpu().unwrap(); // ctx switch safe
    let pc: u64 = cpu.read_reg(Regs::Pc).unwrap();
    log::debug!("#### First exit at {:#x} ####", pc);

    // Save emulator state
    rs.save(&emu, &ResetLevel::RustSnapshot);
    // Catching exceptions
    eh.start(&emu);
    // Setup tunnels cmps
    for cmp in &conf.tunnels_cmps {
        add_tunnels_cmp(cmp.0, &cmp.1, &emu);
    }
    // Setup crash breakpoints
    for bp in &conf.crashes_breakpoints {
        emu.set_breakpoint(*bp);
    }

    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        log::debug!("### Start harness");

        // Reset emulator state
        if unsafe { CRASH_SNAPSHOT } {
            unsafe {
                CRASH_SNAPSHOT = false;
            }
            rs.load(&emu, &conf.snapshot_on_crash);
        } else if unsafe { COUNTER_SNAPSHOT >= conf.snapshot_period } {
            unsafe {
                COUNTER_SNAPSHOT = 0;
            }
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
        cpu = emu.current_cpu().unwrap(); // ctx switch safe
        for mem in conf.input_mem.iter() {
            unsafe {
                write_flash_mem(mem.0, &buffer[..mem.1]);
            }
            buffer = &buffer[mem.1..];
        }

        // Fixed values to memory
        for fixed in conf.input_fixed.iter() {
            let buffer = fixed.1.to_ne_bytes();
            unsafe {
                write_flash_mem(fixed.0, &buffer);
            }
        }

        // Start the emulation
        let mut pc: u64 = cpu.read_reg(Regs::Pc).unwrap();
        log::debug!("Start at {:#x}", pc);
        unsafe {
            if let Err(e) = emu.run() {
                log::error!("{:#?}", e)
            }
        };

        // After the emulator finished
        pc = cpu.read_reg(Regs::Pc).unwrap();
        let r0: u64 = cpu.read_reg(Regs::R0).unwrap();
        log::debug!("End at {:#x} with R0={:#x}", pc, r0);
        unsafe {
            COUNTER_SNAPSHOT += 1;
        }
        // Look for crashes if no sink was hit
        if !conf.harness_sinks.iter().any(|&v| v == pc as GuestAddr) {
            // Don't trigger on exceptions
            if !(ON_CHIP_ADDR..(ON_CHIP_ADDR + 4 * ExceptionType::UNKNOWN as u32))
                .contains(&(pc as u32))
            {
                unsafe {
                    COUNTER_SNAPSHOT = 0;
                    CRASH_SNAPSHOT = true;
                }
                log::info!("Found crash at {:#x}", pc);
                return ExitKind::Crash;
            }
        }
        log::debug!("End harness");
        ExitKind::Ok
    };

    let mut run_client = |state: Option<_>, mut mgr, _core_id| -> Result<(), Error> {
        // Create an observation channel using the coverage map
        let edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                edges_map_mut_slice(),
                addr_of_mut!(MAX_EDGES_NUM),
            ))
            .track_indices()
        };

        // Feedback to rate the interestingness of an input
        let mut feedback = MaxMapFeedback::new(&edges_observer);

        let objective_coverage_feedback =
            MaxMapFeedback::with_name("objective_coverage_feedback", &edges_observer);

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_and_fast!(
            feedback_and_fast!(
                feedback_or!(CrashFeedback::new(), ExceptionFeedback::new()),
                objective_coverage_feedback
            ),
            CustomMetadataFeedback::new(emu) // always true, used to write metadata output whenever a test-case is a solution
        );

        // create a State from scratch
        let cloned_solutions_dir = solutions_dir.clone();
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions,
                // on disk so the user can get them after stopping the fuzzer
                CachedOnDiskCorpus::new(cloned_solutions_dir, 100).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        // Maximum input length
        state.set_max_size(conf.input_total_size);

        // A queue policy to get testcasess from the corpus
        let scheduler = QueueScheduler::new();

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // Configure DrCov helper
        let mut log_drcov_path = log_dir.clone();
        log_drcov_path.push("drcov.log");
        let mut rangemap = RangeMap::<usize, (u16, String)>::new();
        rangemap.insert(
            0x0_usize..0xffff_9000_usize,
            (0, "on-chip-ryzen-zen.bl".to_string()),
        );

        // Configure QEMU hook helper
        let mut hooks = QemuHooks::new(
            emu,
            tuple_list!(
                QemuEdgeCoverageHelper::default(),
                QemuDrCovHelper::new(
                    QemuInstrumentationAddressRangeFilter::None,
                    rangemap,
                    log_drcov_path,
                    false,
                )
            ),
        );

        // Block hooks and write hooks for crash detection
        hooks.blocks(
            Hook::Function(gen_block_hook),
            Hook::Empty,
            Hook::Function(exec_block_hook),
        );
        if !conf.crashes_mmap_no_write_hooks.is_empty() {
            log::debug!("Adding write generation hooks");
            hooks.writes(
                Hook::Function(gen_writes_hook),
                Hook::Function(exec_writes_hook),
                Hook::Function(exec_writes_hook),
                Hook::Function(exec_writes_hook),
                Hook::Function(exec_writes_hook),
                Hook::Function(exec_writes_hook_n),
            );
        } else {
            log::debug!("No write generation hooks");
        }

        let timeout = Duration::new(5, 0); // 5sec
        let mut executor = QemuExecutor::new(
            &mut hooks,
            &mut harness,
            tuple_list!(edges_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .unwrap();

        state
            .load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[input_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &input_dir);
                std::process::exit(0);
            });

        // Setup a mutational stage with a basic bytes mutator
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        log::info!("Starting fuzzing loop");
        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
        log::info!("Ending fuzzing loop");
        println!("END fuzzing loop");
        Ok(())
    };

    // BEGIN Logging
    // Logging of LibAFL events
    let mut log_libafl_path = log_dir.clone();
    log_libafl_path.push("libafl.log");
    let logfile = log_libafl_path;

    let log = RefCell::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(logfile)
            .unwrap(),
    );

    let stdout_cpy = RefCell::new(unsafe {
        let new_fd = dup(io::stdout().as_raw_fd()).unwrap();
        File::from_raw_fd(new_fd)
    });
    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| {
        writeln!(stdout_cpy.borrow_mut(), "{s}").unwrap();
        writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
    });

    // END Logging
    {
        // The shared memory allocator
        let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
        // Catching stdout/stderr

        // Launcher config
        let broker_port = 1337;
        let num_cores = get_run_conf().unwrap().num_cores;
        let cores = Cores::from_cmdline(&format!("0-{num_cores}")).unwrap();

        // Build and run a Launcher
        match Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(broker_port)
            .configuration(EventConfig::from_build_id())
            .monitor(monitor)
            .run_client(&mut run_client)
            .cores(&cores)
            .stdout_file(None)
            .build()
            .launch()
        {
            Ok(()) => (),
            Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
            Err(err) => panic!("Failed to run launcher: {:?}", err),
        }
    }

    // {
    //     // The Monitor trait define how the fuzzer stats are displayed to the user
    //     let mon = SimpleMonitor::new(|s| {
    //         writeln!(&mut stdout_cpy, "{s}").unwrap();
    //         writeln!(log.borrow_mut(), "{s}").unwrap();
    //     });

    //     // The event manager handle the various events generated during the fuzzing loop
    //     // such as the notification of the addition of a new item to the corpus
    //     let mgr = SimpleEventManager::new(mon);

    //     run_client(None, mgr, 1).expect("Client closure failed");
    // }
}

pub fn fuzz() {
    env_logger::init();
    // Generate QEMU start arguments
    let qemu_args = parse_args();
    run(qemu_args)
}
