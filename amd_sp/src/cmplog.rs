//! Comparison-feedback guided mutation (CmpLog + input-to-state) for the flat mailbox input.
//!
//! The guest compares executed inside the filtered address ranges are logged by [`AspCmpLogModule`].
//! `CmpValuesMetadata` is rebuilt by the observer on every execution it is armed for, so the
//! observer ([`GatedCmpLogObserver`]) only records while [`CmpTraceStage`] re-runs the current
//! testcase once; the mutants of the following mutational stage then all see the compares of the
//! testcase they were derived from. Black-box: only operands the guest actually compared are used.
use std::{
    borrow::Cow,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use libafl::{
    corpus::HasCurrentCorpusId,
    executors::{Executor, HasObservers},
    inputs::{BytesInput, HasMutatorBytes},
    mutators::{MutationResult, Mutator},
    observers::{cmp::CmpValuesMetadata, Observer, ObserversTuple},
    stages::{Restartable, RetryCountRestartHelper, Stage},
    state::{HasCurrentTestcase, HasRand},
    Error, HasMetadata, HasNamedMetadata,
};
use libafl_bolts::{rands::Rand, Named};
use libafl_qemu::{
    emu::EmulatorModules,
    modules::{
        cmplog::{
            gen_unique_cmp_ids, trace_cmp1_cmplog, trace_cmp2_cmplog, trace_cmp4_cmplog,
            trace_cmp8_cmplog,
        },
        EmulatorModule, EmulatorModuleTuple,
    },
    qemu::Hook,
    GuestAddr, Qemu,
};
use libafl_targets::{cmps::CMPLOG_ENABLED, CmpLogMap, CmpLogObserver};

/// Set by [`CmpTraceStage`] around its single tracing run.
static ARMED: AtomicBool = AtomicBool::new(false);
/// (traces, total entries, entries of 1/2/4/8 byte compares) for the periodic log line
static TRACES: AtomicU64 = AtomicU64::new(0);

/// `CmpLogModule` that only installs its hooks when enabled (so the default build path is untouched)
/// and looks its address filter up under its own type.
#[derive(Debug)]
pub struct AspCmpLogModule {
    ranges: Vec<std::ops::Range<GuestAddr>>,
    enabled: bool,
}

impl AspCmpLogModule {
    #[must_use]
    pub fn new(enabled: bool, ranges: Vec<std::ops::Range<GuestAddr>>) -> Self {
        Self {
            ranges,
            enabled,
        }
    }

    fn must_instrument(&self, pc: GuestAddr) -> bool {
        self.ranges.iter().any(|r| r.contains(&pc))
    }
}

fn gen_filtered_cmp_ids<ET, I, S>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    state: Option<&mut S>,
    pc: GuestAddr,
    size: usize,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin + HasMetadata,
{
    if !emulator_modules
        .get::<AspCmpLogModule>()
        .is_some_and(|m| m.must_instrument(pc))
    {
        return None;
    }
    // CmpLogModule's own id generator (its filter lookup finds no CmpLogModule and allows all)
    gen_unique_cmp_ids(qemu, emulator_modules, state, pc, size)
}

impl<I, S> EmulatorModule<I, S> for AspCmpLogModule
where
    I: Unpin,
    S: Unpin + HasMetadata,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.enabled {
            emulator_modules.cmps(
                Hook::Function(gen_filtered_cmp_ids::<ET, I, S>),
                Hook::Raw(trace_cmp1_cmplog),
                Hook::Raw(trace_cmp2_cmplog),
                Hook::Raw(trace_cmp4_cmplog),
                Hook::Raw(trace_cmp8_cmplog),
            );
        }
    }
}

/// `CmpLogObserver` that records (and fills `CmpValuesMetadata`) only while the trace stage is running.
#[derive(Debug)]
pub struct GatedCmpLogObserver(Option<CmpLogObserver>);

impl GatedCmpLogObserver {
    /// # Safety
    /// `map` must be the global cmplog map (never moves).
    #[must_use]
    pub unsafe fn new(enabled: bool, map: *mut CmpLogMap) -> Self {
        Self(enabled.then(|| unsafe { CmpLogObserver::with_map_ptr("cmplog", map, true) }))
    }
}

// Observer tuples must be (de)serializable; the cmplog observer holds a raw map pointer, so it is
// never actually persisted (it is rebuilt on restart) and deserializes to the disabled state.
impl serde::Serialize for GatedCmpLogObserver {
    fn serialize<Se: serde::Serializer>(&self, serializer: Se) -> Result<Se::Ok, Se::Error> {
        serializer.serialize_unit()
    }
}

impl<'de> serde::Deserialize<'de> for GatedCmpLogObserver {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <()>::deserialize(deserializer).map(|()| Self(None))
    }
}

impl Named for GatedCmpLogObserver {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("cmplog");
        &NAME
    }
}

impl<I, S: HasMetadata> Observer<I, S> for GatedCmpLogObserver {
    fn pre_exec(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        match &mut self.0 {
            Some(o) if ARMED.load(Ordering::Relaxed) => o.pre_exec(state, input),
            _ => Ok(()),
        }
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &libafl::executors::ExitKind,
    ) -> Result<(), Error> {
        match &mut self.0 {
            Some(o) if ARMED.load(Ordering::Relaxed) => o.post_exec(state, input, exit_kind),
            _ => Ok(()),
        }
    }
}

/// Re-runs the current testcase once (with the cmplog observer armed) so that `CmpValuesMetadata`
/// describes the compares of the testcase about to be mutated.
#[derive(Debug)]
pub struct CmpTraceStage {
    name: Cow<'static, str>,
}

impl CmpTraceStage {
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("cmptrace"),
        }
    }
}

impl Named for CmpTraceStage {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Restartable<S> for CmpTraceStage
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for CmpTraceStage
where
    E: Executor<EM, BytesInput, S, Z> + HasObservers,
    E::Observers: ObserversTuple<BytesInput, S>,
    S: HasMetadata + HasCurrentTestcase<BytesInput>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let input = state.current_input_cloned()?;
        ARMED.store(true, Ordering::Relaxed);
        let res = (|| {
            executor.observers_mut().pre_exec_all(state, &input)?;
            let exit = executor.run_target(fuzzer, state, manager, &input)?;
            executor.observers_mut().post_exec_all(state, &input, &exit)
        })();
        ARMED.store(false, Ordering::Relaxed);
        // the observer disables recording itself; make sure it is off even on error
        unsafe { CMPLOG_ENABLED = 0 };
        res?;
        let n = TRACES.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 20 || n % 200 == 0 {
            if let Ok(m) = state.metadata::<CmpValuesMetadata>() {
                let mut sz = [0usize; 5];
                for c in &m.list {
                    sz[match c {
                        libafl::observers::cmp::CmpValues::U8(_) => 0,
                        libafl::observers::cmp::CmpValues::U16(_) => 1,
                        libafl::observers::cmp::CmpValues::U32(_) => 2,
                        libafl::observers::cmp::CmpValues::U64(_) => 3,
                        libafl::observers::cmp::CmpValues::Bytes(_) => 4,
                    }] += 1;
                }
                log::info!(
                    "cmplog trace #{n}: {} entries (u8 {} u16 {} u32 {} u64 {} bytes {})",
                    m.list.len(),
                    sz[0],
                    sz[1],
                    sz[2],
                    sz[3],
                    sz[4]
                );
            }
        }
        Ok(())
    }
}

/// Runs `inner` but never leaves a command id from `skip` in the command word (e.g. 0x40 waits forever).
pub struct CmdGuard<M> {
    inner: M,
    word_off: usize,
    skip: Vec<u32>,
}

impl<M> CmdGuard<M> {
    #[must_use]
    pub fn new(inner: M, word_off: usize, skip: Vec<u32>) -> Self {
        Self {
            inner,
            word_off,
            skip,
        }
    }
}

impl<M> Named for CmdGuard<M> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CmdGuard");
        &NAME
    }
}

impl<M, S> Mutator<BytesInput, S> for CmdGuard<M>
where
    M: Mutator<BytesInput, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let o = self.word_off;
        let before = input.mutator_bytes().get(o..o + 4).map(|b| b.to_vec());
        let r = self.inner.mutate(state, input)?;
        if let Some(before) = before {
            let b = input.mutator_bytes_mut();
            if b.len() >= o + 4 && self.skip.contains(&(u32::from(b[o + 2]))) {
                b[o..o + 4].copy_from_slice(&before);
            }
        }
        Ok(r)
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

/// Writes a logged compare operand, or a boundary neighbour of it (c-1, c+1, c ^ 0x80000000, !c),
/// into an aligned dword of the mailbox word + argument window, or its low byte into the command id.
/// Plain I2S only finds the exact constant; this covers `cmp x,#c; blt`-style signed/boundary checks.
pub struct CmpBoundaryMutator {
    word_off: usize,
    /// bytes from `word_off` to the end of the argument window
    span: usize,
}

impl CmpBoundaryMutator {
    #[must_use]
    pub fn new(word_off: usize, ptr_fields: bool, arg_len: usize) -> Self {
        Self {
            word_off,
            span: 4 + if ptr_fields { 8 } else { 0 } + arg_len,
        }
    }
}

impl Named for CmpBoundaryMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CmpBoundaryMutator");
        &NAME
    }
}

impl<S: HasRand + HasMetadata> Mutator<BytesInput, S> for CmpBoundaryMutator {
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let Some(meta) = state.metadata_map().get::<CmpValuesMetadata>() else {
            return Ok(MutationResult::Skipped);
        };
        let n = meta.list.len();
        if n == 0 {
            return Ok(MutationResult::Skipped);
        }
        let r0 = state.rand_mut().next();
        let r1 = state.rand_mut().next();
        let r2 = state.rand_mut().next();
        let meta = state.metadata_map().get::<CmpValuesMetadata>().unwrap();
        let Some((a, b, _)) = meta.list[(r0 as usize) % n].to_u64_tuple() else {
            return Ok(MutationResult::Skipped);
        };
        let c = (if r1 & 1 == 0 { a } else { b }) as u32;
        let v = match (r1 >> 1) % 5 {
            0 => c,
            1 => c.wrapping_sub(1),
            2 => c.wrapping_add(1),
            3 => c ^ 0x8000_0000,
            _ => !c,
        };
        let o = self.word_off;
        let bytes = input.mutator_bytes_mut();
        if bytes.len() < o + self.span {
            return Ok(MutationResult::Skipped);
        }
        if (r1 >> 8) % 8 == 0 && v <= 0xff {
            bytes[o + 2] = v as u8; // command id
            return Ok(MutationResult::Mutated);
        }
        let dwords = (self.span - 4) / 4;
        // bias towards the argument header
        let idx = if (r1 >> 16) % 4 == 0 {
            (r2 as usize) % dwords
        } else {
            (r2 as usize) % dwords.min(16)
        };
        let at = o + 4 + idx * 4;
        bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// Flips bit 31 of an aligned dword in the argument header (signed-compare boundary).
pub struct SignFlipMutator {
    word_off: usize,
    span: usize,
}

impl SignFlipMutator {
    #[must_use]
    pub fn new(word_off: usize, ptr_fields: bool, arg_len: usize) -> Self {
        Self {
            word_off,
            span: 4 + if ptr_fields { 8 } else { 0 } + arg_len,
        }
    }
}

impl Named for SignFlipMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("SignFlipMutator");
        &NAME
    }
}

impl<S: HasRand> Mutator<BytesInput, S> for SignFlipMutator {
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let o = self.word_off;
        let bytes = input.mutator_bytes_mut();
        let dwords = (self.span.saturating_sub(4)) / 4;
        if bytes.len() < o + self.span || dwords == 0 {
            return Ok(MutationResult::Skipped);
        }
        let idx = (state.rand_mut().next() as usize) % dwords.min(16);
        bytes[o + 4 + idx * 4 + 3] ^= 0x80;
        Ok(MutationResult::Mutated)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
