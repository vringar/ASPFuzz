//! Field-aware mutator for the mailbox input: `[command word u32][argument buffer]`.
//!
//! Operates on the flat byte input (corpus format unchanged) but mutates by field:
//! command id (bits 23:16), the word framing (pending/response bits), and aligned
//! u32 arguments drawn from a pool of interesting values.
use std::{borrow::Cow, sync::Arc};

use libafl::{
    inputs::{BytesInput, BytesSubInput, HasMutatorBytes},
    mutators::{
        mutations::{
            BitFlipMutator, ByteAddMutator, ByteFlipMutator, ByteInterestingMutator,
            ByteRandMutator, BytesRandSetMutator, DwordInterestingMutator, WordAddMutator,
            WordInterestingMutator,
        },
        MutationResult, Mutator,
    },
    state::HasRand,
    Error,
};
use libafl_bolts::{rands::Rand, Named};
use libasp::mailbox_dict::MailboxDict;

/// Command ids of the Zen2 SecOS BIOS->PSP handler 0x200b4c (psp-etl #835): handled ids, then
/// ids that fall through to the default (status 4) or id 4 (status 8) as negative controls.
const KNOWN_CMDS: &[u32] = &[
    0x2, 0x3, 0x5, 0x6, 0x7, 0x14, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x27, 0x28,
    0x29, 0x2a, 0x2d, 0x30, 0x39, 0x40, 0x47, 0x50, 0x51, 0x5d, // handled
    0x0, 0x1, 0x4, 0x8, 0x2b, 0x2c, 0x2e, 0x2f, // default / status 8
];

/// Interesting u32 values: boundaries, flag bits, buffer-size edges (272 = 0x110), SRAM/flash window edges.
const POOL: &[u32] = &[
    0,
    1,
    2,
    3,
    4,
    8,
    0xf,
    0x10,
    0x1f,
    0x20,
    0x7f,
    0x80,
    0xff,
    0x100,
    0x10f,
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
    // PSP SRAM / SecOS app / flash-window edges
    0x3_f000,
    0x4_0000,
    0x4_f000,
    0x20_0000,
    0x20_8000,
    0x3f_ffff,
    0x0100_0000,
    0x0fff_ffff,
    0x1000_0000,
    0xffff_0000,
];

pub struct MailboxFieldMutator {
    /// byte offset of the command word inside the input
    offset: usize,
    /// size of the argument buffer (excludes the pointer words, which sit between the word and the buffer)
    len: usize,
    /// input carries CmdRspBufAddr lo/hi right behind the word
    ptr_fields: bool,
    /// (offset, count, n_ids) of the irq selector bytes, if the input has any
    irq: Option<(usize, usize, usize)>,
    dict: Option<Arc<MailboxDict>>,
}

impl MailboxFieldMutator {
    #[must_use]
    pub fn new(offset: usize, len: usize, ptr_fields: bool) -> Self {
        Self {
            offset,
            len,
            ptr_fields,
            irq: None,
            dict: None,
        }
    }

    #[must_use]
    pub fn with_dict(mut self, dict: Option<Arc<MailboxDict>>) -> Self {
        self.dict = dict;
        self
    }

    #[must_use]
    pub fn with_irq(mut self, irq: Option<(usize, usize, usize)>) -> Self {
        self.irq = irq;
        self
    }

    fn value<R: Rand>(&self, rand: &mut R) -> u32 {
        match rand.next() % 4 {
            0 => match &self.dict {
                Some(d) if !d.values.is_empty() && rand.next() % 2 == 0 => {
                    d.values[(rand.next() as usize) % d.values.len()]
                }
                _ => POOL[(rand.next() as usize) % POOL.len()],
            },
            1 => {
                let p = 1u32 << (rand.next() % 32);
                match rand.next() % 3 {
                    0 => p.wrapping_sub(1),
                    1 => p,
                    _ => p.wrapping_add(1),
                }
            }
            2 => (rand.next() % 0x400) as u32,
            _ => rand.next() as u32,
        }
    }
}

impl Named for MailboxFieldMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("MailboxFieldMutator");
        &NAME
    }
}

impl<S: HasRand> Mutator<BytesInput, S> for MailboxFieldMutator {
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let (off, len, ptr) = (self.offset, self.len, self.ptr_fields);
        let bytes = input.mutator_bytes_mut();
        if bytes.len() < off + 4 + if ptr { 8 } else { 0 } + len {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        if let Some((at, count, n_ids)) = self.irq {
            // 1 in 4 mutations: change one irq selector (0 = none, 1..=n_ids = that id)
            if bytes.len() >= at + count && rand.next() % 4 == 0 {
                let i = at + (rand.next() as usize) % count;
                bytes[i] = (rand.next() as usize % (n_ids + 1)) as u8;
                return Ok(MutationResult::Mutated);
            }
        }
        let word = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let new_word = match rand.next() % 6 {
            // new command id from the known list, keep framing
            0 => {
                let cmd = match &self.dict {
                    Some(d) if !d.commands.is_empty() => {
                        d.commands[(rand.next() as usize) % d.commands.len()].id
                    }
                    _ => KNOWN_CMDS[(rand.next() as usize) % KNOWN_CMDS.len()],
                };
                (word & !0x00ff_0000) | ((cmd & 0xff) << 16)
            }
            // new random command id
            1 => (word & !0x00ff_0000) | (((rand.next() % 0x100) as u32) << 16),
            // framing: host writes cmd with bit31 (Ready) clear; a set bit31 is never picked up (no reply, 10 s timeout)
            2 => word & !0x8000_0000,
            // recovery / reset-required bits (AMD 55758 p.75-77)
            3 => word ^ 0x4000_0000,
            4 => word ^ 0x2000_0000,
            // an argument dword instead
            _ => word,
        };
        if new_word != word {
            bytes[off..off + 4].copy_from_slice(&new_word.to_le_bytes());
            return Ok(MutationResult::Mutated);
        }
        if ptr && rand.next() % 3 == 0 {
            // CmdRspBufAddr lo/hi: the mapper keeps the low 12 bits; x86 slots span 0x0400_0000..0xfc00_0000,
            // secure DRAM is 0xfffd_fb00_0000 (librarian catalog)
            let lo = match rand.next() % 4 {
                0 => 0xfb00_0000 | ((rand.next() as u32) & 0xfff),
                1 => {
                    0x0400_0000
                        + (((rand.next() as u32) % 0xf8) << 20)
                        + ((rand.next() as u32) & 0xfff)
                }
                2 => (rand.next() as u32) & 0xffff_f000, // aligned
                _ => self.value(rand),
            };
            let lo = match &self.dict {
                Some(d) if !d.buf_lo_low12.is_empty() && rand.next() % 3 == 0 => {
                    (lo & !0xfff)
                        | (d.buf_lo_low12[(rand.next() as usize) % d.buf_lo_low12.len()] & 0xfff)
                }
                _ => lo,
            };
            let hi = match rand.next() % 4 {
                0 => 0xfffd,
                1 => 0,
                2 => 1 << (rand.next() % 16),
                _ => (rand.next() as u32) & 0xffff,
            };
            let at = off + 4 + 4 * (rand.next() as usize % 2);
            let v = if at == off + 4 { lo } else { hi };
            bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
            return Ok(MutationResult::Mutated);
        }
        let arg_start = off + 4 + if ptr { 8 } else { 0 };
        if let Some(d) = &self.dict {
            // typed field of the current command (catalog arg layout), 1 in 2
            let cmd = (u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) >> 16) & 0xff;
            let fields = d
                .commands
                .iter()
                .find(|c| c.id == cmd)
                .map_or(&[][..], |c| &c.fields[..]);
            if !fields.is_empty() && rand.next() % 2 == 0 {
                let f = &fields[(rand.next() as usize) % fields.len()];
                if f.offset + f.size <= len && matches!(f.size, 1 | 4 | 8) {
                    let v = if f.size == 8 {
                        u64::from(self.value(rand)) | (u64::from(self.value(rand)) << 32)
                    } else {
                        u64::from(self.value(rand))
                    };
                    let at = arg_start + f.offset;
                    bytes[at..at + f.size].copy_from_slice(&v.to_le_bytes()[..f.size]);
                    return Ok(MutationResult::Mutated);
                }
            }
        }
        let dwords = len / 4;
        if dwords == 0 {
            return Ok(MutationResult::Skipped);
        }
        // bias towards the first 16 dwords, where the argument headers live
        let idx = if rand.next() % 4 == 0 {
            (rand.next() as usize) % dwords
        } else {
            (rand.next() as usize) % dwords.min(16)
        };
        let at = off + 4 + if ptr { 8 } else { 0 } + idx * 4;
        bytes[at..at + 4].copy_from_slice(&self.value(rand).to_le_bytes());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// Stock length-preserving byte mutators applied only to the argument window `[start, start + len)`,
/// leaving the command word, pointer words and trailing IRQ selector bytes alone.
pub struct ArgWindowHavoc {
    start: usize,
    len: usize,
    bit: BitFlipMutator,
    flip: ByteFlipMutator,
    rand: ByteRandMutator,
    add: ByteAddMutator,
    wadd: WordAddMutator,
    bint: ByteInterestingMutator,
    wint: WordInterestingMutator,
    dint: DwordInterestingMutator,
    set: BytesRandSetMutator,
}

impl ArgWindowHavoc {
    #[must_use]
    pub fn new(start: usize, len: usize) -> Self {
        Self {
            start,
            len,
            bit: BitFlipMutator::new(),
            flip: ByteFlipMutator::new(),
            rand: ByteRandMutator::new(),
            add: ByteAddMutator::new(),
            wadd: WordAddMutator::new(),
            bint: ByteInterestingMutator::new(),
            wint: WordInterestingMutator::new(),
            dint: DwordInterestingMutator::new(),
            set: BytesRandSetMutator::new(),
        }
    }
}

impl Named for ArgWindowHavoc {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("ArgWindowHavoc");
        &NAME
    }
}

impl<S: HasRand> Mutator<BytesInput, S> for ArgWindowHavoc {
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        if input.mutator_bytes().len() < self.start + self.len || self.len == 0 {
            return Ok(MutationResult::Skipped);
        }
        let pick = state.rand_mut().next() % 9;
        let mut win = BytesSubInput::new(input, self.start..self.start + self.len);
        match pick {
            0 => self.bit.mutate(state, &mut win),
            1 => self.flip.mutate(state, &mut win),
            2 => self.rand.mutate(state, &mut win),
            3 => self.add.mutate(state, &mut win),
            4 => self.wadd.mutate(state, &mut win),
            5 => self.bint.mutate(state, &mut win),
            6 => self.wint.mutate(state, &mut win),
            7 => self.dint.mutate(state, &mut win),
            _ => self.set.mutate(state, &mut win),
        }
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
