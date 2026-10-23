//! Typed mailbox session: a sequence of BIOS->PSP messages, each laid out from the catalog.
//! Mutators are field-aware (havoc only inside typed fields), derive TotalSize at render time
//! (a deliberately wrong size is an explicit `LenSpec`), and perturb command sequences around
//! a valid prefix. All randomness comes from the fuzzer state (deterministic).
//! Vendored from PSPReverse/LibAFL `claude/structured-proto` (75cc3ae4); adapted: default buffer
//! pointer from the yaml, header fields (offset < 8) are not mutated as typed fields, session length
//! cap, opaque-struct byte mutator and the weighted schedule.
use std::{borrow::Cow, num::NonZeroUsize, sync::Arc};

use libafl::{
    corpus::CorpusId,
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use libafl_bolts::{rands::Rand, HasLen, Named};
use serde::{Deserialize, Serialize};

use super::catalog::Catalog;

/// Length field: derived from the buffer by default, deliberately wrong only when mutated so.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub enum LenSpec {
    #[default]
    Derived,
    Override(u32),
    Delta(i32),
}

impl LenSpec {
    pub fn resolve(&self, buf_len: usize) -> u32 {
        match self {
            LenSpec::Derived => buf_len as u32,
            LenSpec::Override(v) => *v,
            LenSpec::Delta(d) => (buf_len as u32).wrapping_add_signed(*d),
        }
    }
}

/// One mailbox message: command id, argument buffer (TotalSize@0, Status@4, args from 8),
/// and the CmdRspBufAddr lo/hi words.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct MbMsg {
    pub cmd: u32,
    pub buf: Vec<u8>,
    pub total_size: LenSpec,
    pub buf_lo: u32,
    pub buf_hi: u32,
    /// framing bits 30:24 of the command word (recovery / reset-required, AMD 55758 p.76-77); bit 31 stays
    /// clear because a set Ready bit is never picked up by the worker
    #[serde(default)]
    pub flags: u8,
}
impl Input for MbMsg {}

/// A session: messages replayed in order. Own type instead of `ListInput<MbMsg>` because the scheduler
/// needs `HasLen` (orphan rule), and it avoids the `multipart_inputs` feature. On disk: postcard of this struct.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct MbSession {
    parts: Vec<MbMsg>,
}
impl Input for MbSession {}
impl HasLen for MbSession {
    fn len(&self) -> usize {
        self.parts.len()
    }
}
impl MbSession {
    pub fn new(parts: Vec<MbMsg>) -> Self {
        Self { parts }
    }
    pub fn parts(&self) -> &[MbMsg] {
        &self.parts
    }
    pub fn parts_mut(&mut self) -> &mut [MbMsg] {
        &mut self.parts
    }
    pub fn insert_part(&mut self, idx: usize, m: MbMsg) {
        self.parts.insert(idx, m);
    }
    pub fn remove_part_at_index(&mut self, idx: usize) {
        self.parts.remove(idx);
    }
    pub fn pop_part(&mut self) -> Option<MbMsg> {
        self.parts.pop()
    }
}

impl MbMsg {
    /// Bytes to place in the mapped buffer. TotalSize is derived from the buffer unless overridden.
    pub fn render(&self) -> Vec<u8> {
        let mut b = self.buf.clone();
        if b.len() < 8 {
            b.resize(8, 0);
        }
        let total = self.total_size.resolve(b.len());
        b[0..4].copy_from_slice(&total.to_le_bytes());
        b
    }
}

const POOL: &[u64] = &[
    0,
    1,
    2,
    3,
    4,
    8,
    0xf,
    0x10,
    0x20,
    0x7f,
    0x80,
    0xff,
    0x100,
    0x110,
    0x111,
    0x1000,
    0xffff,
    0x1_0000,
    0x7fff_ffff,
    0x8000_0000,
    0x8000_0001,
    0xffff_fffe,
    0xffff_ffff,
    0x3_f000,
    0x4_0000,
    0x20_0000,
    0x0100_0000,
    0x0400_0000,
    0xfb00_0000,
    0x1_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    0xfffd_fb00_0000,
    u64::MAX,
];

/// Command ids the Zen2 SecOS handler 0x200b4c dispatches (psp-etl #835/#922); the rest is the default (status 4).
pub const HANDLED: &[u32] = &[
    0x2, 0x3, 0x5, 0x6, 0x7, 0x14, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x27, 0x28,
    0x29, 0x2a, 0x2d, 0x30, 0x39, 0x40, 0x47, 0x50, 0x51, 0x5d,
];

/// Known-good command orders (preconditions of the stateful commands, board #922/#925).
pub const VALID_ORDERS: &[&[u32]] = &[&[0x1b, 0x06], &[0x02, 0x28, 0x29, 0x2a]];

fn below<S: HasRand>(state: &mut S, n: usize) -> usize {
    state.rand_mut().below(NonZeroUsize::new(n).unwrap())
}

fn mask(width: usize) -> u64 {
    if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (width * 8)) - 1
    }
}

fn write_le(buf: &mut [u8], off: usize, width: usize, v: u64) -> bool {
    if off + width > buf.len() {
        return false;
    }
    buf[off..off + width].copy_from_slice(&v.to_le_bytes()[..width]);
    true
}

fn read_le(buf: &[u8], off: usize, width: usize) -> Option<u64> {
    let s = buf.get(off..off + width)?;
    let mut a = [0u8; 8];
    a[..width].copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// A value for a field of `width` bytes: pool, power of two +-1, small, the sign bit, or `old` perturbed.
fn typed_value<S: HasRand>(state: &mut S, width: usize, old: u64) -> u64 {
    let bits = (width * 8) as u32;
    let v = match below(state, 6) {
        0 => POOL[below(state, POOL.len())],
        1 => {
            let p = 1u64 << below(state, bits as usize);
            [p.wrapping_sub(1), p, p.wrapping_add(1)][below(state, 3)]
        }
        2 => below(state, 0x400) as u64,
        3 => old ^ (1u64 << (bits - 1)), // flip the sign bit: signed/unsigned size checks
        4 => old.wrapping_add_signed(below(state, 33) as i64 - 16),
        _ => old ^ (1u64 << below(state, bits as usize)),
    };
    v & mask(width)
}

/// Typed scalar fields past the 8-byte header (TotalSize/Status are derived / written by the firmware).
fn scalars(cat: &Catalog, cmd: u32) -> Vec<(usize, usize)> {
    cat.command(cmd)
        .map(|c| {
            c.arg_layout
                .iter()
                .filter_map(|f| f.scalar())
                .filter(|&(o, _)| o >= 8)
                .collect()
        })
        .unwrap_or_default()
}

/// Fill the typed fields of `buf` with fresh values.
fn fill_fields<S: HasRand>(state: &mut S, cat: &Catalog, cmd: u32, buf: &mut [u8]) {
    for (off, w) in scalars(cat, cmd) {
        let v = typed_value(state, w, 0);
        write_le(buf, off, w, v);
    }
}

fn new_msg<S: HasRand>(state: &mut S, cat: &Catalog, cmd: u32) -> MbMsg {
    let len = cat.command(cmd).map_or(16, |c| c.buf_len());
    let mut buf = vec![0u8; len];
    fill_fields(state, cat, cmd, &mut buf);
    MbMsg {
        cmd,
        buf,
        total_size: LenSpec::Derived,
        buf_lo: cat.default_ptr.0,
        buf_hi: cat.default_ptr.1,
        flags: 0,
    }
}

/// Benign message: zeroed buffer (all-zero arguments), default pointer, derived TotalSize.
pub fn benign_msg(cat: &Catalog, cmd: u32) -> MbMsg {
    let len = cat.command(cmd).map_or(16, |c| c.buf_len());
    MbMsg {
        cmd,
        buf: vec![0u8; len],
        total_size: LenSpec::Derived,
        buf_lo: cat.default_ptr.0,
        buf_hi: cat.default_ptr.1,
        flags: 0,
    }
}

/// Initial sessions: one message per catalog command that the firmware handles and that returns
/// (0x06 alone loops forever, 0x40 never returns: both are excluded; their valid forms are covered by
/// the 0x1b,0x06 seed), plus the valid orders. Seeds are benign (zero arguments) and never replay a crash.
pub fn initial_sessions(cat: &Catalog) -> Vec<MbSession> {
    const NOT_ALONE: &[u32] = &[0x06, 0x40];
    let mut out: Vec<MbSession> = cat
        .commands
        .iter()
        .filter(|c| HANDLED.contains(&c.id) && !NOT_ALONE.contains(&c.id))
        .map(|c| MbSession::new(vec![benign_msg(cat, c.id)]))
        .collect();
    for order in VALID_ORDERS {
        if order.iter().all(|&i| cat.command(i).is_some()) {
            out.push(MbSession::new(
                order.iter().map(|&i| benign_msg(cat, i)).collect(),
            ));
        }
    }
    out
}

macro_rules! named {
    ($t:ty, $n:expr) => {
        impl Named for $t {
            fn name(&self) -> &Cow<'static, str> {
                static N: Cow<'static, str> = Cow::Borrowed($n);
                &N
            }
        }
    };
}

/// Mutate ONE typed field of ONE message (havoc only inside typed fields).
pub struct FieldMutator {
    pub catalog: Arc<Catalog>,
}
named!(FieldMutator, "MbFieldMutator");
impl<S: HasRand> Mutator<MbSession, S> for FieldMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        if n == 0 {
            return Ok(MutationResult::Skipped);
        }
        let mi = below(state, n);
        let sc = scalars(&self.catalog, input.parts()[mi].cmd);
        if sc.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let (off, w) = sc[below(state, sc.len())];
        let old = read_le(&input.parts()[mi].buf, off, w).unwrap_or(0);
        let v = typed_value(state, w, old);
        let ok = write_le(&mut input.parts_mut()[mi].buf, off, w, v);
        Ok(if ok && v != old {
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        })
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

/// Byte-level havoc inside the opaque `struct(N B)` fields the typed mutators leave alone.
pub struct OpaqueMutator {
    pub catalog: Arc<Catalog>,
}
named!(OpaqueMutator, "MbOpaqueMutator");
impl<S: HasRand> Mutator<MbSession, S> for OpaqueMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        if n == 0 {
            return Ok(MutationResult::Skipped);
        }
        let mi = below(state, n);
        let Some(c) = self.catalog.command(input.parts()[mi].cmd) else {
            return Ok(MutationResult::Skipped);
        };
        let regs = c.opaque();
        if regs.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let (off, sz) = regs[below(state, regs.len())];
        let buf = &mut input.parts_mut()[mi].buf;
        let end = (off + sz).min(buf.len());
        if off >= end {
            return Ok(MutationResult::Skipped);
        }
        let i = off + below(state, end - off);
        match below(state, 3) {
            0 => buf[i] ^= 1 << below(state, 8),
            1 => buf[i] = below(state, 256) as u8,
            _ => buf[i] = [0, 1, 0x7f, 0x80, 0xff][below(state, 5)],
        }
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

/// Make TotalSize deliberately inconsistent with the buffer (the knob; keep its weight low).
pub struct SizeLieMutator;
named!(SizeLieMutator, "MbSizeLieMutator");
impl<S: HasRand> Mutator<MbSession, S> for SizeLieMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        if n == 0 {
            return Ok(MutationResult::Skipped);
        }
        let mi = below(state, n);
        if below(state, 4) == 0 {
            // framing knob: flip one of the command-word bits 30:24
            input.parts_mut()[mi].flags ^= 1 << below(state, 7);
            return Ok(MutationResult::Mutated);
        }
        input.parts_mut()[mi].total_size = match below(state, 3) {
            0 => LenSpec::Override(POOL[below(state, POOL.len())] as u32),
            1 => LenSpec::Delta(below(state, 17) as i32 - 8),
            _ => LenSpec::Derived, // allows returning to a consistent size
        };
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

/// CmdRspBufAddr lo/hi: near the default (mapped) buffer, 4 KiB-aligned or not, secure-DRAM-ish and wild values.
pub struct BufPtrMutator {
    pub default_ptr: (u32, u32),
}
named!(BufPtrMutator, "MbBufPtrMutator");
impl<S: HasRand> Mutator<MbSession, S> for BufPtrMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        if n == 0 {
            return Ok(MutationResult::Skipped);
        }
        let mi = below(state, n);
        let r = state.rand_mut().next();
        let (dlo, dhi) = self.default_ptr;
        let m = &mut input.parts_mut()[mi];
        match r % 5 {
            // default page, odd low 12 bits (alignment checks)
            0 => {
                m.buf_lo = (dlo & !0xfff) | ((r >> 8) as u32 & 0xfff);
                m.buf_hi = dhi;
            }
            // back to the default
            1 => (m.buf_lo, m.buf_hi) = (dlo, dhi),
            2 => m.buf_lo = ((r >> 8) as u32) & 0xffff_f000,
            3 => {
                m.buf_lo = 0xfb00_0000 | ((r >> 8) as u32 & 0xfff);
                m.buf_hi = 0xfffd;
            }
            _ => {
                m.buf_lo = POOL[(r >> 8) as usize % POOL.len()] as u32;
                m.buf_hi = (POOL[(r >> 20) as usize % POOL.len()] >> 32) as u32;
            }
        }
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

/// Change a message's command (arguments regenerated from the new layout, buffer resized).
pub struct CmdMutator {
    pub catalog: Arc<Catalog>,
}
named!(CmdMutator, "MbCmdMutator");
impl<S: HasRand> Mutator<MbSession, S> for CmdMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        let k = self.catalog.commands.len();
        if n == 0 || k == 0 {
            return Ok(MutationResult::Skipped);
        }
        let mi = below(state, n);
        // 1 in 8: an id that is not in the catalog (negative control, should give status 4)
        let id = if below(state, 8) == 0 {
            below(state, 0x100) as u32
        } else {
            self.catalog.commands[below(state, k)].id
        };
        if id == input.parts()[mi].cmd {
            return Ok(MutationResult::Skipped);
        }
        let mut m = new_msg(state, &self.catalog, id);
        let old = &input.parts()[mi];
        (m.buf_lo, m.buf_hi) = (old.buf_lo, old.buf_hi);
        input.parts_mut()[mi] = m;
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

/// Sequence mutator: start from a VALID prefix (a known-good command order, e.g. 0x1b before 0x06),
/// then perturb: drop, duplicate, swap adjacent, insert a random command, truncate.
/// Sessions never grow past `max_len`.
pub struct SequenceMutator {
    pub catalog: Arc<Catalog>,
    /// known-good command orders (preconditions), e.g. [[0x1b, 0x06], [0x02, 0x28, 0x29, 0x2a]]
    pub valid: Vec<Vec<u32>>,
    pub max_len: usize,
}
named!(SequenceMutator, "MbSequenceMutator");
impl<S: HasRand> Mutator<MbSession, S> for SequenceMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        let k = self.catalog.commands.len();
        if k == 0 {
            return Ok(MutationResult::Skipped);
        }
        match below(state, 6) {
            // prepend the missing prerequisites of a valid sequence prefix, keeping the rest of the session
            0 if !self.valid.is_empty() => {
                let seq = &self.valid[below(state, self.valid.len())];
                let take = 1 + below(state, seq.len());
                let have: Vec<u32> = input.parts().iter().map(|m| m.cmd).collect();
                let mut parts: Vec<MbMsg> = seq[..take]
                    .iter()
                    .filter(|i| !have.contains(i))
                    .map(|&i| new_msg(state, &self.catalog, i))
                    .collect();
                if parts.is_empty() {
                    return Ok(MutationResult::Skipped);
                }
                parts.extend(input.parts().iter().cloned());
                parts.truncate(self.max_len);
                *input = MbSession::new(parts);
            }
            1 if n > 1 => input.remove_part_at_index(below(state, n)),
            2 if n > 0 && n < self.max_len => {
                let i = below(state, n);
                let c = input.parts()[i].clone();
                input.insert_part(i, c);
            }
            3 if n > 1 => {
                let i = below(state, n - 1);
                input.parts_mut().swap(i, i + 1);
            }
            4 if n > 1 => {
                let keep = 1 + below(state, n - 1);
                while input.parts().len() > keep {
                    input.pop_part();
                }
            }
            _ if n < self.max_len => {
                let id = self.catalog.commands[below(state, k)].id;
                let m = new_msg(state, &self.catalog, id);
                input.insert_part(below(state, n + 1), m);
            }
            _ => return Ok(MutationResult::Skipped),
        }
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

/// The whole schedule: Field 50 / Cmd 15 / Sequence 15 / BufPtr 10 / SizeLie 5 / Opaque 5, with
/// 1..=3 stacked mutations per call. An empty session gets a generated message first.
pub struct SessionMutator {
    field: FieldMutator,
    cmd: CmdMutator,
    seq: SequenceMutator,
    ptr: BufPtrMutator,
    lie: SizeLieMutator,
    opaque: OpaqueMutator,
}
named!(SessionMutator, "MbSessionMutator");

impl SessionMutator {
    pub fn new(catalog: Arc<Catalog>, max_len: usize) -> Self {
        let valid = VALID_ORDERS.iter().map(|o| o.to_vec()).collect();
        Self {
            field: FieldMutator {
                catalog: catalog.clone(),
            },
            cmd: CmdMutator {
                catalog: catalog.clone(),
            },
            seq: SequenceMutator {
                catalog: catalog.clone(),
                valid,
                max_len,
            },
            ptr: BufPtrMutator {
                default_ptr: catalog.default_ptr,
            },
            lie: SizeLieMutator,
            opaque: OpaqueMutator { catalog },
        }
    }
}

impl<S: HasRand> Mutator<MbSession, S> for SessionMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let mut res = MutationResult::Skipped;
        for _ in 0..1 + below(state, 3) {
            let r = match below(state, 100) {
                0..50 => self.field.mutate(state, input)?,
                50..65 => self.cmd.mutate(state, input)?,
                65..80 => self.seq.mutate(state, input)?,
                80..90 => self.ptr.mutate(state, input)?,
                90..95 => self.lie.mutate(state, input)?,
                _ => self.opaque.mutate(state, input)?,
            };
            if r == MutationResult::Mutated {
                res = r;
            }
        }
        Ok(res)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use libafl::state::NopState;

    use super::*;

    // Synthetic catalog (the real one is AMD-derived and local-only, never committed).
    const CAT: &str = r#"{"commands":[
      {"id":2,"name":"A","arg_layout":[{"name":"x","type":"u64","offset":8},{"name":"y","type":"u32","offset":16},{"name":"s","type":"BLOB 8 B","offset":20}],"maps_buffer":false},
      {"id":27,"name":"B"},
      {"id":6,"name":"C","arg_layout":[{"name":"f","type":"u8","offset":8}],"arg_size":32}]}"#;

    fn cat() -> Arc<Catalog> {
        Arc::new(Catalog::from_json(CAT).unwrap())
    }

    #[test]
    fn render_derives_total_size_unless_overridden() {
        let mut m = MbMsg {
            cmd: 2,
            buf: vec![0; 20],
            total_size: LenSpec::Derived,
            buf_lo: 0,
            buf_hi: 0,
            flags: 0,
        };
        assert_eq!(&m.render()[0..4], &20u32.to_le_bytes());
        m.total_size = LenSpec::Override(0x8000_0000);
        assert_eq!(&m.render()[0..4], &0x8000_0000u32.to_le_bytes());
        m.total_size = LenSpec::Delta(-1);
        assert_eq!(&m.render()[0..4], &19u32.to_le_bytes());
    }

    #[test]
    fn seeds_are_benign_and_skip_hanging_commands() {
        let c = cat();
        let seeds = initial_sessions(&c);
        let ids: Vec<Vec<u32>> = seeds
            .iter()
            .map(|s| s.parts().iter().map(|m| m.cmd).collect())
            .collect();
        assert!(ids.contains(&vec![2]));
        assert!(!ids.contains(&vec![6]));
        assert!(seeds
            .iter()
            .all(|s| s.parts().iter().all(|m| m.buf.iter().all(|&b| b == 0))));
    }

    #[test]
    fn schedule_keeps_layout_and_session_cap() {
        let c = cat();
        let mut st: NopState<MbSession> = NopState::new();
        let mut sm = SessionMutator::new(c.clone(), 4);
        let mut s = MbSession::new(vec![new_msg(&mut st, &c, 2)]);
        for _ in 0..2000 {
            sm.mutate(&mut st, &mut s).unwrap();
            assert!(s.parts().len() <= 4);
            for m in s.parts() {
                if let Some(cmd) = c.command(m.cmd) {
                    assert_eq!(m.buf.len(), cmd.buf_len(), "cmd {}", m.cmd);
                    assert_eq!(&m.buf[0..8], &[0u8; 8], "header untouched");
                }
                assert!(m.render().len() >= 8);
            }
        }
    }

    #[test]
    fn sequences_reach_valid_orders() {
        let c = cat();
        let mut st: NopState<MbSession> = NopState::new();
        let mut sm = SequenceMutator {
            catalog: c,
            valid: vec![vec![27, 6]],
            max_len: 6,
        };
        let mut s = MbSession::new(vec![]);
        let mut saw = false;
        for _ in 0..300 {
            sm.mutate(&mut st, &mut s).unwrap();
            saw |= s.parts().iter().map(|m| m.cmd).collect::<Vec<_>>() == vec![27, 6];
        }
        assert!(saw);
    }

    /// Optional: parse the real (local-only) catalog if MAILBOX_CATALOG points at it.
    #[test]
    fn real_catalog_parses_if_present() {
        let Ok(p) = std::env::var("MAILBOX_CATALOG") else {
            return;
        };
        let c = Catalog::from_json(&std::fs::read_to_string(p).unwrap()).unwrap();
        assert!(c.commands.len() > 10);
        assert!(initial_sessions(&c).len() > 10);
    }
}
