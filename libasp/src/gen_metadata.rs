//! Generating metadata whenever a test-case is an objective
//! Saves all register values
use std::borrow::Cow;

use libafl::prelude::*;
use libafl_bolts::{impl_serdeany, Named};

use libafl_qemu::*;

use log;
use serde::{Deserialize, Serialize};

use crate::MiscMetadata;

/// A custom testcase metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterMetadata {
    r0: String,
    r1: String,
    r2: String,
    r3: String,
    r4: String,
    r5: String,
    r6: String,
    r7: String,
    r8: String,
    r9: String,
    r10: String,
    r11: String,
    r12: String,
    sp: String,
    pc: String,
    lr: String,
    cpsr: String,
}

impl_serdeany!(RegisterMetadata);

impl RegisterMetadata {
    /// Creates a new [`RegisterMetadata`]
    #[must_use]
    pub fn new(regs: Vec<u64>) -> Self {
        Self {
            r0: format!("{:#010x}", regs[0]),
            r1: format!("{:#010x}", regs[1]),
            r2: format!("{:#010x}", regs[2]),
            r3: format!("{:#010x}", regs[3]),
            r4: format!("{:#010x}", regs[4]),
            r5: format!("{:#010x}", regs[5]),
            r6: format!("{:#010x}", regs[6]),
            r7: format!("{:#010x}", regs[7]),
            r8: format!("{:#010x}", regs[8]),
            r9: format!("{:#010x}", regs[9]),
            r10: format!("{:#010x}", regs[10]),
            r11: format!("{:#010x}", regs[11]),
            r12: format!("{:#010x}", regs[12]),
            sp: format!("{:#010x}", regs[13]),
            pc: format!("{:#010x}", regs[14]),
            lr: format!("{:#010x}", regs[15]),
            cpsr: format!("{:#010x}", regs[16]),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CustomMetadataFeedback {
    emulator: Qemu,
}
impl<S> StateInitializer<S> for CustomMetadataFeedback {}
impl<EM, I, OT, S> Feedback<EM, I, OT, S> for CustomMetadataFeedback
where
    S: HasMetadata,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        _em: &mut EM,
        _ot: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        // Read regs
        let mut regs = Vec::new();
        log::info!("Number of cpus is: {}", self.emulator.num_cpus());
        for r in Regs::iter() {
            regs.push(self.emulator.cpu_from_index(0).read_reg(r).unwrap());
        }
        testcase.add_metadata(RegisterMetadata::new(regs));
        if let Ok(mbox_values) = state.metadata::<MiscMetadata>() {
            testcase.add_metadata(mbox_values.clone());
        }
        Ok(())
    }
}

impl Named for CustomMetadataFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("CustomMetadataFeedback")
    }
}

impl CustomMetadataFeedback {
    /// Creates a new [`CustomMetadataFeedback`]
    #[must_use]
    pub fn new(emulator: Qemu) -> Self {
        Self { emulator }
    }
}
