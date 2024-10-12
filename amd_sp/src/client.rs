use libafl::prelude::*;
use libafl_bolts::prelude::*;
use libafl_qemu::{
    modules::{
        edges::{edges_map_mut_ptr, EDGES_MAP_SIZE_IN_USE, MAX_EDGES_FOUND},
        DrCovModule, EmulatorModule, EmulatorModuleTuple, StdAddressFilter,
        StdEdgeCoverageModule,
    },
    Emulator, Qemu, QemuExecutor,
    QemuExitReason, Regs,
};
use libasp::{
    get_run_conf, CustomMetadataFeedback, ExceptionFeedback, ExceptionHandler,
    Reset, ResetLevel, ResetState,
};
use rangemap::RangeMap;
use std::{
    path::PathBuf,
    ptr::addr_of_mut,
    time::Duration,
};

use crate::harness;


pub fn run_client<SP>(
    qemu_args: Vec<String>,
    state: Option<MyState>,
    solutions_dir: PathBuf,
    log_dir: PathBuf,
    input_dir: PathBuf,
    mut mgr: SimpleEventManager<SimpleMonitor<SP>, MyState>, /*LlmpRestartingEventManager<
                                                                 (),
                                                                 MyState,
                                                                 SP,
                                                             >,*/
) -> Result<(), Error>
where
    //SP: ShMemProvider,
    SP: FnMut(&str),
{
    let conf = &get_run_conf().unwrap().yaml_config;

    let emu = Qemu::init(&qemu_args).expect("Failed to create QEMU instance");
    // Create an observation channel using the coverage map
    let edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_SIZE_IN_USE),
            addr_of_mut!(MAX_EDGES_FOUND),
        ))
        .track_indices()
    };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");
    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&edges_observer),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );

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
        log::debug!("Creating new state");
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
    state.set_max_size(conf.input.total_size());

    // TODO: There is a better scheduling policy??
    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut modules = configure_modules(log_dir)
        .ok_or(Error::illegal_state("Couldn't configure EmulatorModules"))?;

    // Set fuzzing sinks
    for sink in &conf.harness.sinks {
        emu.set_breakpoint(*sink);
    }
    // Configure ResetState and ExceptionHandler helpers
    let mut rs = ResetState::new(conf.flash.size);
    let mut eh = ExceptionHandler::new();

    // Go to FUZZ_START
    let addr = conf.harness.start;
    emu.set_breakpoint(addr);
    unsafe {
        match emu.run() {
            Ok(QemuExitReason::Breakpoint(guest_addr)) => {
                assert_eq!(
                    guest_addr, addr,
                    "Guest addr: {guest_addr:#x}, Conf harness: {addr:#x}"
                );
            }
            _ => panic!("Unexpected QEMU exit."),
        }
    };
    emu.remove_breakpoint(conf.harness.start);
    modules
        .match_first_type_mut::<DrCovModule<StdAddressFilter>>()
        .unwrap()
        .update_address_filter(emu, StdAddressFilter::deny_list(vec![]));
    let cpu = emu.current_cpu().unwrap(); // ctx switch safe
    let pc: u64 = cpu.read_reg(Regs::Pc).unwrap();
    log::debug!("#### First exit at {:#x} ####", pc);
    // Save emulator state
    rs.save(&emu, &ResetLevel::RustSnapshot);
    // Catching exceptions
    eh.start(&emu);
    // Setup crash breakpoints
    for bp in &conf.crashes.breakpoints {
        emu.set_breakpoint(*bp);
    }

    // The closure that we want to fuzz
    let mut harness = harness::create_harness(rs, emu);
    let timeout = Duration::new(15, 0); // 5sec
    let emulator = Emulator::empty().qemu(emu).modules(modules).build()?;
    let mut executor = QemuExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )
    .expect("Failed to create QemuExecutor");

    // // Instead of calling the timeout handler and restart the process, trigger a breakpoint ASAP
    // executor.break_on_timeout();

    // if state.must_load_initial_inputs() {
    //     state
    //         .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[input_dir.clone()])
    //         .unwrap_or_else(|_| {
    //             log::error!("Failed to load initial corpus at {:?}", &input_dir);
    //             std::process::exit(0);
    //         });
    //     log::info!(
    //         "We imported {} inputs from {:?}.",
    //         state.corpus().count(),
    //         &input_dir
    //     );
    // }

    // // Setup a mutational stage with a basic bytes mutator
    // let mutator = StdScheduledMutator::new(havoc_mutations());
    // let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // log::info!("Starting fuzzing loop");
    // fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    // log::info!("Ending fuzzing loop");
    // println!("END fuzzing loop");
    Ok(())
}

fn configure_modules(log_dir: PathBuf) -> Option<impl EmulatorModuleTuple<MyState> + Sized> {
    // Configure DrCov helper
    let mut log_drcov_path = log_dir.clone();
    log_drcov_path.push("drcov.log");
    let mut rangemap = RangeMap::<usize, (u16, String)>::new();

    // TODO: Should this be dynamic?
    rangemap.insert(
        0x0_usize..0xffff_9000_usize,
        (0, "on-chip-ryzen-zen.bl".to_string()),
    );
    let filter = StdAddressFilter::deny_list(vec![0x0_u32..0xffff_ffff_u32]);
    // Configure QEMU hook helper
    let dr_cov_module = DrCovModule::builder()
        .module_mapping(rangemap)
        .filename(log_drcov_path)
        .filter(filter)
        .full_trace(false)
        .build();
    let modules = tuple_list!(StdEdgeCoverageModule::builder().build(), dr_cov_module);

    Some(modules)
}
