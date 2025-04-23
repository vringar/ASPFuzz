use crate::{config::YAMLConfig, MailboxValues};
use libafl::HasMetadata;
use libafl_qemu::{
    modules::{EmulatorModule, EmulatorModuleTuple},
    EmulatorModules, Qemu,
};
use serde::{Deserialize, Serialize};

/// This module is a general utility module for things that weren't big enough to warrant their own module
///
/// This includes the Tunnels, since they are fully stateless and so need neither a Module nor Metadata
/// It is also responsible for updating the range map for `DrCov` and the Interupt Base address for the Exception Handler
#[derive(Debug)]
pub struct LibAspModule {
    config: YAMLConfig,
}

impl LibAspModule {
    #[must_use]
    pub fn new(conf: YAMLConfig) -> Self {
        LibAspModule { config: conf }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]

pub struct MiscMetadata {
    pub mailbox_values: MailboxValues,
}
libafl_bolts::impl_serdeany!(MiscMetadata);

impl<I, S> EmulatorModule<I, S> for LibAspModule
where
    S: Unpin + HasMetadata,
    I: Unpin,
{
    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: EmulatorModuleTuple<I, S>,
    {
        // This function gets run before the VM starts
        self.config.tunnels.setup(modules);
    }
}
