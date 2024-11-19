use std::ptr::addr_of_mut;

use crate::{config::YAMLConfig, read_mailbox_value, MailboxValues};
use libafl::{inputs::UsesInput, HasMetadata};
use libafl_qemu::{
    modules::{
        EmulatorModule, EmulatorModuleTuple, NopAddressFilter, NopPageFilter, NOP_ADDRESS_FILTER,
        NOP_PAGE_FILTER,
    },
    EmulatorModules,
};
use serde::{Deserialize, Serialize};

/// This module is a general utility module for things that weren't big enough to warrant their own module
///
/// This includes the Tunnels, since they are fully stateless and so need neither a Module nor Metadata
/// It is also responsible for updating the range map for DrCov and the Interupt Base address for the Exception Handler
#[derive(Debug)]
pub struct LibAspModule {
    config: YAMLConfig,
}

impl LibAspModule {
    pub fn new(conf: YAMLConfig) -> Self {
        LibAspModule { config: conf }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]

pub struct MiscMetadata {
    mailbox_values: MailboxValues,
}
libafl_bolts::impl_serdeany!(MiscMetadata);

impl<S> EmulatorModule<S> for LibAspModule
where
    S: UsesInput + Unpin + HasMetadata,
{
    type ModuleAddressFilter = NopAddressFilter;

    type ModulePageFilter = NopPageFilter;

    fn address_filter(&self) -> &Self::ModuleAddressFilter {
        &NopAddressFilter
    }

    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
        unsafe { addr_of_mut!(NOP_ADDRESS_FILTER).as_mut().unwrap().get_mut() }
    }

    fn page_filter(&self) -> &Self::ModulePageFilter {
        &NopPageFilter
    }

    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter {
        unsafe { addr_of_mut!(NOP_PAGE_FILTER).as_mut().unwrap().get_mut() }
    }

    fn post_qemu_init<ET>(&self, modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        // This function gets run before the VM starts
        self.config.tunnels.setup(modules);
    }

    fn post_exec<OT, ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
        _input: &<S as UsesInput>::Input,
        _observers: &mut OT,
        _exit_kind: &mut libafl::prelude::ExitKind,
    ) where
        OT: libafl::prelude::ObserversTuple<<S as UsesInput>::Input, S>,
        ET: EmulatorModuleTuple<S>,
    {
        if self.config.input.has_mailbox() {
            state.add_metadata(MiscMetadata {
                mailbox_values: read_mailbox_value(&emulator_modules.qemu().cpu_from_index(0))
                    .expect("Failed to read mailbox"),
            });
        }
    }
}
