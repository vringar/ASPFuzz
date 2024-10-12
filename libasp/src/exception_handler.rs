use libafl::prelude::*;
/// Catching and handling ARM CPU exceptions durign the test-case execution
use libafl_qemu::*;
use modules::{
    EmulatorModule, NopAddressFilter, NopPageFilter, NOP_ADDRESS_FILTER, NOP_PAGE_FILTER,
};
use strum::FromRepr;

use core::fmt::Debug;
use libafl_bolts::Named;
use log;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, ptr::addr_of_mut};

#[derive(Copy, Clone, Serialize, Deserialize, Debug, FromRepr, EnumIter)]
#[repr(u32)]
pub enum ExceptionType {
    RESET = 0,
    UNDEF = 1,
    SVC = 2,
    PREAB = 3,
    DATAB = 4,
    HYP = 5,
    IRQ = 6,
    FIQ = 7,
    UNKNOWN = 8,
}

// TODO make this depedent on machine register
// for exception handler base
pub const ON_CHIP_ADDR: GuestAddr = 0x100;

#[derive(Debug, Default)]
pub struct ExceptionHandler {
    exception_vector_base: GuestAddr,
    hook_ids: Vec<InstructionHookId>,
}

impl ExceptionHandler {
    pub fn new() -> Self {
        let exception_vector_base = ON_CHIP_ADDR;
        Self {
            exception_vector_base,
            hook_ids: vec![],
        }
    }
    pub fn stop(&self) {
        for &hook_id in &self.hook_ids {
            hook_id.remove(true);
        }
    }
}

impl<S> EmulatorModule<S> for ExceptionHandler
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

    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, _state: &mut S)
    where
        ET: modules::EmulatorModuleTuple<S>,
    {
        for enum_value in ExceptionType::iter() {
            let exception_addr = self.exception_vector_base + 4 * (enum_value as u32);
            emulator_modules.instructions(
                exception_addr,
                Hook::Closure(Box::new(
                    move |hks: &mut EmulatorModules<ET, S>, state: Option<&mut S>, _pc| {
                        let state =
                            state.expect("State should be present when generating block hooks");

                        let meta = state
                            .metadata_map_mut()
                            .get_or_insert_with(ExceptionHandlerMetadata::default);
                        meta.triggered_exception = Some(enum_value);
                        let emu = hks.qemu();
                        let sp: u32 = emu.read_reg(Regs::Sp).unwrap();
                        let lr: u32 = emu.read_reg(Regs::Lr).unwrap();
                        log::debug!("Exception:{enum_value:?} sp: {sp:#x} lr: {lr:#x}");
                        emu.current_cpu().unwrap().trigger_breakpoint();
                    },
                )),
                true,
            );
        }
    }
}
#[derive(Debug, Default, Serialize, Deserialize)]

struct ExceptionHandlerMetadata {
    triggered_exception: Option<ExceptionType>,
}
libafl_bolts::impl_serdeany!(ExceptionHandlerMetadata);
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ExceptionFeedback {}

impl<S> StateInitializer<S> for ExceptionFeedback {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for ExceptionFeedback
where
    S: HasMetadata,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let meta = state
            .metadata_map_mut()
            .get_or_insert_with(ExceptionHandlerMetadata::default);
        if meta.triggered_exception.is_some() {
            log::info!("ExceptionFeedback=True");
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Named for ExceptionFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ExceptionFeedback")
    }
}
