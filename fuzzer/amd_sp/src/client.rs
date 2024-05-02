use libafl::prelude::*;
use libafl_bolts::prelude::*;
use libafl_qemu::{
    edges::{edges_map_mut_ptr, EDGES_MAP_SIZE_IN_USE, MAX_EDGES_FOUND},
    sys::TCGTemp,
    GuestAddr, Hook, MemAccessInfo, Qemu, QemuDrCovHelper, QemuEdgeCoverageHelper, QemuExecutor,
    QemuHelperTuple, QemuHooks, QemuInstrumentationAddressRangeFilter, Regs,
};
use libasp::{borrow_global_conf, get_run_conf, CustomMetadataFeedback, ExceptionFeedback};
use rangemap::RangeMap;
use std::{
    path::PathBuf,
    ptr::addr_of_mut,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::Duration,
};

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
    for no_exec in conf.crashes_mmap_no_exec.iter() {
        if src >= no_exec[0] && src < no_exec[1] {
            log::debug!("Generate block:");
            log::debug!("> src: {:#x}", src);
            log::debug!("> id: {:#x}", id);
            hooks.qemu().current_cpu().unwrap().trigger_breakpoint();
            return Some(id);
        }
    }

    if !conf.crashes_mmap_no_write_flash_fn.is_empty() && conf.crashes_mmap_flash_read_fn == src {
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

type MyState =
    StdState<BytesInput, InMemoryCorpus<BytesInput>, RomuDuoJrRand, CachedOnDiskCorpus<BytesInput>>;

pub fn run_client<SP>(
    emu: Qemu,
    state: Option<MyState>,
    solutions_dir: PathBuf,
    log_dir: PathBuf,
    input_dir: PathBuf,
    mut mgr: LlmpRestartingEventManager<(), MyState, SP>,
    mut harness: impl FnMut(&BytesInput) -> ExitKind,
) -> Result<(), Error>
where
    SP: ShMemProvider,
{
    let conf = &get_run_conf().unwrap().yaml_config;
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

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[input_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &input_dir);
                std::process::exit(0);
            });
        println!(
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
