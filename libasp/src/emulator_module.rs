//! This module contains an implementation of the
//!

use std::ptr::addr_of_mut;

use crate::config::YAMLConfig;
use libafl::inputs::UsesInput;
use libafl_qemu::{
    modules::{
        EmulatorModule, EmulatorModuleTuple, NopAddressFilter, NopPageFilter, NOP_ADDRESS_FILTER,
        NOP_PAGE_FILTER,
    },
    EmulatorModules,
};

#[derive(Debug)]
pub struct LibAspModule {
    config: YAMLConfig,
}

impl LibAspModule {
    pub fn new(conf: YAMLConfig) -> Self {
        LibAspModule { config: conf }
    }
}
impl<S> EmulatorModule<S> for LibAspModule
where
    S: UsesInput + Unpin,
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

    fn init_module<ET>(&self, modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        // This function gets run before the VM starts
        self.config.tunnels.setup(modules);
    }

    fn first_exec<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>, _state: &mut S)
    where
        ET: EmulatorModuleTuple<S>,
    {
        // We've hit the initial breakpoint
    }
}
