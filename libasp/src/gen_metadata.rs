use std::borrow::Cow;

use libafl::prelude::*;
use libafl_bolts::{impl_serdeany, Named};
/// Generating metadata whenever a test-case is an objective
/// Saves all register values
use libafl_qemu::*;

use log;
use serde::{Deserialize, Serialize};

/// A custom testcase metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct CustomMetadata {
    pub r0: String,
    pub r1: String,
    pub r2: String,
    pub r3: String,
    pub r4: String,
    pub r5: String,
    pub r6: String,
    pub r7: String,
    pub r8: String,
    pub r9: String,
    pub r10: String,
    pub r11: String,
    pub r12: String,
    pub sp: String,
    pub pc: String,
    pub lr: String,
    pub cpsr: String,
}

impl_serdeany!(CustomMetadata);

impl CustomMetadata {
    /// Creates a new [`struct@CustomMetadata`]
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
impl<EM, I, OT, S> Feedback<EM, I, OT, S> for CustomMetadataFeedback {
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
        _state: &mut S,
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
        testcase.add_metadata(CustomMetadata::new(regs));
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
