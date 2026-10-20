//! Session harness: one fuzz input is a list of mailbox messages replayed in order within ONE
//! snapshot restore (yaml `structured_session: true`). After a message's reply sink the guest is
//! run on to the idle WFI (the harness start address), where the mailbox worker blocks on the
//! doorbell again, and the next message is delivered. The snapshot is restored once, after the session.
use core::{ptr::addr_of_mut, time::Duration};
use std::{
    collections::HashMap,
    path::PathBuf,
    process,
    sync::{Arc, Mutex},
    time::Instant,
};

use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{ClientDescription, EventConfig, Launcher},
    executors::ExitKind,
    feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::Input,
    monitors::MultiMonitor,
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    current_nanos,
    ownedref::OwnedMutSlice,
    prelude::Cores,
    rands::{RomuDuoJrRand, StdRand},
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Prepend},
};
use libafl_qemu::{
    executor::QemuExecutor,
    modules::{
        edges::StdEdgeCoverageModuleBuilder,
        utils::filters::{HasAddressFilter, StdAddressFilter},
        DrCovModule,
    },
    Emulator, GuestAddr, QemuExitError, QemuExitReason, QemuParams, QemuShutdownCause,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
use libasp::{
    config::{
        access_observer::{AccessObserverFeedback, AccessObserverObserver},
        get_run_conf,
    },
    read_mailbox_value, CustomMetadataFeedback, ExceptionFeedback, MiscMetadata, RegisterMetadata,
};
use rangemap::RangeMap;

use super::{
    catalog::Catalog,
    mailbox::{initial_sessions, MbSession, SessionMutator},
};
use crate::setup::setup_directory_structure;

pub type SessState =
    StdState<CachedOnDiskCorpus<MbSession>, MbSession, RomuDuoJrRand, OnDiskCorpus<MbSession>>;

/// Reply status marker: the sink was hit but the reply bit (31) was not set.
const NO_REPLY: u32 = 0xffff_ffff;
/// Reply status marker: the message timed out (no sink within the time budget).
const TIMED_OUT: u32 = 0xffff_fffe;
/// "previous command" marker for the first message of a session
const FIRST: u32 = 0xffff;

/// (previous cmd, cmd, status) -> count, dumped to `<run>/logs/replies_<pid>.txt` every few seconds
/// (the process is killed, not stopped, so a final dump is not an option).
struct ReplyStats {
    counts: HashMap<(u32, u32, u32), u64>,
    last_dump: Instant,
    path: PathBuf,
}

impl ReplyStats {
    fn record(&mut self, prev: u32, cmd: u32, status: u32) {
        *self.counts.entry((prev, cmd, status)).or_default() += 1;
        if self.last_dump.elapsed() > Duration::from_secs(10) {
            self.last_dump = Instant::now();
            let mut rows: Vec<_> = self.counts.iter().collect();
            rows.sort();
            let text: String = rows
                .iter()
                .map(|((p, c, s), n)| format!("{p:#x} {c:#x} {s:#x} {n}\n"))
                .collect();
            let _ = std::fs::write(&self.path, text);
        }
    }
}

enum Out {
    Bp(GuestAddr),
    Timeout,
    Crash,
}

/// `args`: the QEMU command line from `parse_args` (already parsed by the caller, which owns the logger).
pub fn fuzz_session(args: Box<Vec<String>>) -> Result<(), Error> {
    let conf = get_run_conf().ok_or(Error::empty_optional("No run configuration found"))?;
    let (input_dir, log_dir, solutions_dir) =
        setup_directory_structure(&conf.run_dir, &conf.config_path)?;

    let (lo, hi, _) = conf
        .yaml_config
        .input
        .mailbox_window()
        .ok_or(Error::illegal_argument("structured_session needs input.mailbox_config"))?;
    let catalog_path = conf
        .yaml_config
        .mailbox_catalog
        .as_deref()
        .ok_or(Error::illegal_argument("structured_session needs mailbox_catalog"))?;
    let mut catalog = Catalog::load(catalog_path).map_err(Error::illegal_argument)?;
    catalog.default_ptr = (lo, hi);
    let catalog = Arc::new(catalog);
    let max_len = conf.yaml_config.session_len.unwrap_or(6).max(1);

    // Benign initial sessions (serde of the session input is the on-disk corpus format)
    for (i, s) in initial_sessions(&catalog).iter().enumerate() {
        s.to_file(input_dir.join(format!("seed{i:03}")))?;
    }
    let input_dir = Box::new(input_dir);

    let mut run_client = move |state: Option<SessState>,
                               mut mgr,
                               client_description: ClientDescription| {
        log::error!("Starting session client");
        let conf = get_run_conf().unwrap();
        let mut log_drcov_path = log_dir.clone();
        log_drcov_path.push("drcov.log");
        let mut rangemap = RangeMap::<u64, (u16, String)>::new();
        rangemap.insert(
            0x0_u64..0xffff_9000_u64,
            (0, "on-chip-ryzen-zen.bl".to_string()),
        );
        #[allow(clippy::single_range_in_vec_init)]
        let filter =
            StdAddressFilter::deny_list(vec![(0x0 as GuestAddr)..(0xffff_ffff as GuestAddr)]);
        let dr_cov_module = DrCovModule::builder()
            .module_mapping(rangemap)
            .path(log_drcov_path)
            .filter(filter)
            .full_trace(false)
            .build();
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                addr_of_mut!(MAX_EDGES_FOUND),
            ))
            .track_indices()
        };
        let emulator_modules = conf
            .yaml_config
            .get_emulator_modules::<SessState>()
            .prepend(
                StdEdgeCoverageModuleBuilder::default()
                    .map_observer(edges_observer.as_mut())
                    .build()?,
            )
            .prepend(dr_cov_module);
        let args = args.as_ref();
        let emulator = Emulator::empty()
            .qemu_parameters(QemuParams::Cli(args.clone()))
            .modules(emulator_modules)
            .build()?;
        let qemu = emulator.qemu();
        // The start address is the idle WFI where the mailbox worker waits for the doorbell
        let idle = conf.yaml_config.harness.start;
        qemu.set_breakpoint(idle);
        unsafe {
            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(a)) => assert_eq!(a, idle, "Guest addr: {a:#x}"),
                _ => panic!("Unexpected QEMU exit."),
            }
        }
        qemu.remove_breakpoint(idle);
        let sinks = conf.yaml_config.harness.sinks.clone();
        for &s in &sinks {
            qemu.set_breakpoint(s);
        }
        let snap = emulator.create_fast_snapshot(true);
        log::error!("Snapshot created");

        let log_mbox = std::env::var_os("ASPFUZZ_LOG_MBOX").is_some();
        let stats = Mutex::new(ReplyStats {
            counts: HashMap::new(),
            last_dump: Instant::now(),
            path: log_dir.join(format!("replies_{}.txt", process::id())),
        });

        let mut harness = |emulator: &mut Emulator<_, _, _, _, _, SessState, _>,
                           state: &mut SessState,
                           input: &MbSession| {
            let dr_cov_module = emulator
                .modules_mut()
                .get_mut::<DrCovModule<StdAddressFilter>>()
                .unwrap();
            dr_cov_module.update_address_filter(qemu, StdAddressFilter::allow_list(vec![]));

            // One run of the guest until the next breakpoint, with the bookkeeping the flat harness does
            let run = |state: &mut SessState| -> Out {
                unsafe {
                    let res = qemu.run();
                    state.metadata_map_mut().insert(RegisterMetadata::new(qemu));
                    let mailbox_values = read_mailbox_value(&qemu.cpu_from_index(0).unwrap())
                        .expect("Failed to read mailbox");
                    state.add_metadata(MiscMetadata { mailbox_values });
                    match res {
                        Ok(QemuExitReason::Breakpoint(pc)) => Out::Bp(pc),
                        Ok(QemuExitReason::Timeout) => Out::Timeout,
                        Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
                            log::error!("HostSignal");
                            signal.handle();
                            Out::Crash
                        }
                        Err(QemuExitError::UnexpectedExit) => Out::Crash,
                        e => panic!("Unexpected QEMU exit: {e:?}."),
                    }
                }
            };

            let mut ret = ExitKind::Ok;
            let mut prev = FIRST;
            let mut parked = false;
            let n = input.parts().len().min(max_len);
            for (i, m) in input.parts().iter().take(max_len).enumerate() {
                let word = (m.cmd << 16) & 0x7fff_ffff;
                conf.yaml_config
                    .input
                    .apply_mailbox_message(word, m.buf_lo, m.buf_hi, &m.render());
                match run(state) {
                    Out::Bp(pc) if sinks.contains(&pc) => {
                        let out = read_mailbox_value(&qemu.cpu_from_index(0).unwrap())
                            .map_or(0, |v| v.mbox);
                        let status = if out & 0x8000_0000 != 0 { out & 0x7fff_ffff } else { NO_REPLY };
                        stats.lock().unwrap().record(prev, m.cmd, status);
                        if log_mbox {
                            log::error!("session msg {i} cmd={:#x} in={word:#010x} out={out:#010x}", m.cmd);
                        }
                        if status == NO_REPLY {
                            break; // the worker is not back at the doorbell: nothing to deliver to
                        }
                        prev = m.cmd;
                        if i + 1 < n {
                            // run on to the idle WFI: the worker waits for the next doorbell
                            for &s in &sinks {
                                qemu.remove_breakpoint(s);
                            }
                            qemu.set_breakpoint(idle);
                            parked = true;
                            match run(state) {
                                Out::Bp(pc) if pc == idle => {
                                    qemu.remove_breakpoint(idle);
                                    for &s in &sinks {
                                        qemu.set_breakpoint(s);
                                    }
                                    parked = false;
                                }
                                Out::Timeout => {
                                    stats.lock().unwrap().record(prev, m.cmd, TIMED_OUT);
                                    ret = ExitKind::Timeout;
                                    break;
                                }
                                Out::Bp(pc) => {
                                    log::error!("session: unexpected exit at PC {pc:#x} after reply");
                                    ret = ExitKind::Crash;
                                    break;
                                }
                                Out::Crash => {
                                    ret = ExitKind::Crash;
                                    break;
                                }
                            }
                        }
                    }
                    Out::Bp(pc) => {
                        log::error!("Unexpected exit at PC: {pc:#x}");
                        ret = ExitKind::Crash;
                        break;
                    }
                    Out::Timeout => {
                        log::error!("Timeout in message {i} (cmd {:#x})", m.cmd);
                        stats.lock().unwrap().record(prev, m.cmd, TIMED_OUT);
                        ret = ExitKind::Timeout;
                        break;
                    }
                    Out::Crash => {
                        log::error!("Crash in message {i} (cmd {:#x})", m.cmd);
                        ret = ExitKind::Crash;
                        break;
                    }
                }
            }
            if parked {
                qemu.remove_breakpoint(idle);
                for &s in &sinks {
                    qemu.set_breakpoint(s);
                }
            }
            if ret != ExitKind::Crash {
                // one restore per session (the flat harness's Crash path does not restore either)
                unsafe { emulator.restore_fast_snapshot(snap) };
            }
            ret
        };

        let time_observer = TimeObserver::new("time");
        let time_feedback = TimeFeedback::new(&time_observer);
        let access_observer = AccessObserverObserver::new(conf.yaml_config.crashes.x86.clone());
        let mut feedback = feedback_or!(MaxMapFeedback::new(&edges_observer), time_feedback.clone());
        let objective_map_feedback =
            MaxMapFeedback::with_name("objective_map_feedback", &edges_observer);
        let mut objective = feedback_or_fast!(
            feedback_or!(
                AccessObserverFeedback::new(&access_observer),
                feedback_and_fast!(
                    feedback_or_fast!(CrashFeedback::new(), ExceptionFeedback::default()),
                    objective_map_feedback,
                ),
            ),
            feedback_or!(CustomMetadataFeedback::default(), time_feedback)
        );

        let mut state: SessState = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::with_seed(current_nanos() + client_description.id() as u64),
                CachedOnDiskCorpus::new(&*input_dir, 1000).unwrap(),
                OnDiskCorpus::new(solutions_dir.clone()).unwrap(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        // The executor timeout covers a whole session; 500 ms in the SecOS idle harnesses
        let timeout = Duration::from_millis(conf.yaml_config.timeout_ms.unwrap_or(10_000));
        let mut executor = QemuExecutor::new(
            emulator,
            &mut harness,
            tuple_list!(edges_observer, time_observer, access_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("Failed to create QemuExecutor");
        executor.break_on_timeout();

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[input_dir.as_ref().clone()])
                .unwrap_or_else(|_| {
                    log::error!("Failed to load initial corpus at {:?}", &input_dir);
                    process::exit(0);
                });
            log::info!("We imported {} inputs from disk.", state.corpus().count());
        }

        let mut stages = tuple_list!(StdMutationalStage::new(SessionMutator::new(catalog.clone(), max_len)));
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let monitor = MultiMonitor::new(|s| log::info!(target: "aspfuzz_updates","{s}"));
    let num_cores = get_run_conf().unwrap().num_cores;
    let cores = Cores::from_cmdline(&format!("0-{num_cores}")).unwrap();
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .build()
        .launch()
    {
        Ok(()) => Ok(()),
        Err(Error::ShuttingDown) => {
            log::error!("Fuzzing stopped by user. Good bye.");
            Ok(())
        }
        Err(err) => Err(err),
    }
}
