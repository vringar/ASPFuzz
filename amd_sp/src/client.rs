use libafl::prelude::*;
use libafl_bolts::prelude::*;
use libafl_qemu::{
    edges::{edges_map_mut_ptr, EDGES_MAP_SIZE_IN_USE, MAX_EDGES_FOUND},
    sys::TCGTemp,
    GuestAddr, HasInstrumentationFilter, Hook, MemAccessInfo, Qemu, QemuDrCovHelper,
    QemuEdgeCoverageHelper, QemuExecutor, QemuExitReason, QemuHelperTuple, QemuHooks,
    QemuInstrumentationAddressRangeFilter, Regs,
};
use libasp::{
    borrow_global_conf, get_run_conf, setup_tunnels, CustomMetadataFeedback, ExceptionFeedback,
    ExceptionHandler, RegionWithHoles, Reset, ResetLevel, ResetState,
};
use rangemap::RangeMap;
use std::fmt::Debug;
use std::ops::Range;
use std::{
    env,
    path::PathBuf,
    ptr::addr_of_mut,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::Duration,
};

use crate::harness;
pub const ON_CHIP_ADDR: GuestAddr = 0xffff_0000;

type MyState = StdState<
    BytesInput,
    CachedOnDiskCorpus<BytesInput>,
    RomuDuoJrRand,
    CachedOnDiskCorpus<BytesInput>,
>;

pub fn run_client<SP>(
    qemu_args: Vec<String>,
    state: Option<MyState>,
    solutions_dir: PathBuf,
    log_dir: PathBuf,
    input_dir: PathBuf,
    mut mgr: /*SimpleEventManager<SimpleMonitor<SP>,MyState>*/ LlmpRestartingEventManager<
        (),
        MyState,
        SP,
    >,
) -> Result<(), Error>
where
    SP: ShMemProvider,
    //SP: FnMut(&str)
{
    let conf = &get_run_conf().unwrap().yaml_config;
    let env: Vec<(String, String)> = env::vars().collect();

    let emu = Qemu::init(&qemu_args, &env).unwrap();

    // Create an observation channel using the coverage map
    let edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_SIZE_IN_USE),
            addr_of_mut!(MAX_EDGES_FOUND),
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
            CachedOnDiskCorpus::new(input_dir.clone(), 100).unwrap(),
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
    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut hooks = setup_hooks(log_dir, emu, conf);

    // Set fuzzing sinks
    for sink in &conf.harness.sinks {
        emu.set_breakpoint(*sink);
    }

    // Configure ResetState and ExceptionHandler helpers
    let mut rs = ResetState::new(conf.flash.size);
    let mut eh = ExceptionHandler::new(ON_CHIP_ADDR);

    // Go to FUZZ_START
    let addr = conf.harness.start;
    emu.set_breakpoint(addr);
    unsafe {
        match emu.run() {
            Ok(QemuExitReason::Breakpoint(guest_addr)) => {
                assert_eq!(guest_addr, conf.harness.start);
                println!("Guest addr: {guest_addr}, Conf harness: {addr}")
            }
            _ => panic!("Unexpected QEMU exit."),
        }
    };
    emu.remove_breakpoint(conf.harness.start);
    hooks
        .helpers_mut()
        .match_first_type_mut::<QemuDrCovHelper>()
        .unwrap()
        .update_filter(QemuInstrumentationAddressRangeFilter::None, &emu);
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

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[input_dir.clone()])
            .unwrap_or_else(|_| {
                log::error!("Failed to load initial corpus at {:?}", &input_dir);
                std::process::exit(0);
            });
        log::info!(
            "We imported {} inputs from {:?}.",
            state.corpus().count(),
            &input_dir
        );
    }

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    log::info!("Starting fuzzing loop");
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    log::info!("Ending fuzzing loop");
    println!("END fuzzing loop");
    Ok(())
}

fn setup_hooks(
    log_dir: PathBuf,
    emu: Qemu,
    conf: &libasp::YAMLConfig,
) -> Box<QemuHooks<impl QemuHelperTuple<MyState> + Debug, MyState>> {
    // Configure DrCov helper
    let mut log_drcov_path = log_dir.clone();
    log_drcov_path.push("drcov.log");
    let mut rangemap = RangeMap::<usize, (u16, String)>::new();

    // TODO: Should this be dynamic?
    rangemap.insert(
        0x0_usize..0xffff_9000_usize,
        (0, "on-chip-ryzen-zen.bl".to_string()),
    );
    let filter = QemuInstrumentationAddressRangeFilter::DenyList(vec![Range {
        start: 0x0_u32,
        end: 0xffff_9000_u32,
    }]);
    // Configure QEMU hook helper
    let hooks = QemuHooks::new(
        emu,
        tuple_list!(
            QemuEdgeCoverageHelper::default(),
            QemuDrCovHelper::new(filter, rangemap, log_drcov_path, false,),
        ),
    );
    setup_tunnels(&hooks, conf);
    // Block hooks and write hooks for crash detection
    hooks.blocks(
        Hook::Function(gen_block_hook),
        Hook::Empty,
        Hook::Function(exec_block_hook),
    );
    if !conf.crashes.mmap.no_write_hooks.is_empty() {
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
    hooks
}

static COUNTER_WRITE_HOOKS: AtomicU64 = AtomicU64::new(0);
static COUNTER_EDGE_HOOKS: AtomicU64 = AtomicU64::new(0);
static FLASH_READ_HOOK_ID: OnceLock<u64> = OnceLock::new();

fn gen_block_hook<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _id: Option<&mut S>,
    src: GuestAddr,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let id = COUNTER_EDGE_HOOKS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let conf = borrow_global_conf().unwrap();
    for no_exec in conf.crashes.mmap.no_exec.iter() {
        if src >= no_exec.begin && src < no_exec.end {
            log::debug!("Generate block:");
            log::debug!("> src: {:#x}", src);
            log::debug!("> id: {:#x}", id);
            hooks.qemu().current_cpu().unwrap().trigger_breakpoint();
            return Some(id);
        }
    }

    if !conf.crashes.mmap.no_write_flash_fn.is_empty() && conf.crashes.mmap.flash_read_fn == src {
        log::debug!("Adding block hook for flash_read_fn");
        let _ = FLASH_READ_HOOK_ID.set(id);
        return Some(id);
    }
    None
}
fn exec_block_hook<QT, S>(hooks: &mut QemuHooks<QT, S>, _data_maybe: Option<&mut S>, id: u64)
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emu = hooks.qemu();
    if FLASH_READ_HOOK_ID.get().unwrap() == &id {
        let conf = borrow_global_conf().unwrap();
        let cpu = emu.current_cpu().unwrap();
        let pc: u64 = cpu.read_reg(Regs::Pc).unwrap();
        log::debug!("Flash read fn id was hit");
        if pc as GuestAddr == conf.crashes.mmap.flash_read_fn {
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
            for area in &conf.crashes.mmap.no_write_flash_fn {
                if (area.begin >= cpy_dest_start && area.begin < cpy_dest_end)
                    || (area.end >= cpy_dest_start && area.end < cpy_dest_end)
                {
                    log::debug!(
                        "Flash read fn writes to [{:#010x}, {:#010x}]",
                        area.begin,
                        area.end
                    );
                    let cpy_lr: GuestAddr =
                        cpu.read_reg::<libafl_qemu::Regs, u64>(Regs::Lr).unwrap() as GuestAddr;
                    log::debug!("Flash read fn called from {:#010x}", cpy_lr);
                    if !area.holes.contains(&cpy_lr) {
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
    for RegionWithHoles {
        holes: no_write, ..
    } in conf.crashes.mmap.no_write_hooks.iter()
    {
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
    for &RegionWithHoles { begin, end, .. } in conf.crashes.mmap.no_write_hooks.iter() {
        if addr >= begin && addr < end {
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
    for no_write in conf.crashes.mmap.no_write_hooks.iter() {
        if addr >= no_write.begin && addr < no_write.end {
            log::debug!("Execute writes:");
            log::debug!("> id: {:#x}", id);
            log::debug!("> addr: {:#x}", addr);
            log::debug!("> size: {}", size);
            // log::debug!("> data: {}", (todo!() as u32));
            hooks.qemu().current_cpu().unwrap().trigger_breakpoint();
        }
    }
}
