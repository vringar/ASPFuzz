use libafl::prelude::*;
use libafl_bolts::core_affinity::Cores;
use libafl_bolts::current_time;
use libafl_bolts::shmem::ShMemProvider;
use libafl_bolts::shmem::StdShMemProvider;
use libafl_qemu::*;
use libasp::*;

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


use crate::client;
use crate::harness;
use crate::setup::parse_args;

pub const ON_CHIP_ADDR: GuestAddr = 0xffff_0000;

static mut COUNTER_EDGE_HOOKS: usize = 0;
static mut COUNTER_SNAPSHOT: usize = 0;
static mut CRASH_SNAPSHOT: bool = false;



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
    emu.set_breakpoint(conf.harness_start);
    unsafe {
        match emu.run() {
            Ok(QemuExitReason::Breakpoint(_)) => {}
            _ => panic!("Unexpected QEMU exit."),
        }
    };
    emu.remove_breakpoint(conf.harness_start);
    let cpu = emu.current_cpu().unwrap(); // ctx switch safe
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
    let harness = harness::create_harness(rs, emu);

    let mut run_client = |state: Option<_>, mgr, _core_id| -> Result<(), Error> {
        client::run_client(emu, state, solutions_dir.clone(), log_dir.clone(), input_dir.clone(), mgr, harness.clone() )
    };

    // BEGIN Logging
    // Logging of LibAFL events
    let logfile = {
        let mut log_libafl_path = log_dir.clone();
        log_libafl_path.push("libafl.log");
        log_libafl_path
    };
    

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
    // Catching stdout/stderr
    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| {
        writeln!(stdout_cpy.borrow_mut(), "{s}").unwrap();
        writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
    });
    let mut std_out_path = log_dir.clone();
    std_out_path.push("stdout.log");
    // END Logging
    {
        // The shared memory allocator
        let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

        // Launcher config
        let broker_port = 1337;
        let num_cores = get_run_conf().unwrap().num_cores;
        let cores = Cores::from_cmdline(&format!("0-{num_cores}")).unwrap();

        // Option<StdState<BytesInput, InMemoryCorpus<BytesInput>, RomuDuoJrRand, CachedOnDiskCorpus<BytesInput>>>, LlmpRestartingEventManager<(), StdState<BytesInput, InMemoryCorpus<BytesInput>, RomuDuoJrRand, CachedOnDiskCorpus<BytesInput>>, CommonUnixShMemProvider>, CoreId
        // Build and run a Launcher
        match Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(broker_port)
            .configuration(EventConfig::from_build_id())
            .monitor(monitor)
            .run_client(&mut run_client)
            .cores(&cores)
            .stdout_file(Some(
                std_out_path.to_str().unwrap()
            ))
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
