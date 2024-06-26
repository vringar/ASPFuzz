use libafl::prelude::*;
/// Catching and handling ARM CPU exceptions durign the test-case execution
use libafl_qemu::*;

use core::fmt::Debug;
use libafl_bolts::Named;
use log;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Copy, Clone)]
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

impl From<u32> for ExceptionType {
    fn from(orig: u32) -> Self {
        match orig {
            0 => ExceptionType::RESET,
            1 => ExceptionType::UNDEF,
            2 => ExceptionType::SVC,
            3 => ExceptionType::PREAB,
            4 => ExceptionType::DATAB,
            5 => ExceptionType::HYP,
            6 => ExceptionType::IRQ,
            7 => ExceptionType::FIQ,
            _ => ExceptionType::UNKNOWN,
        }
    }
}

// TODO make this depedent on machine register
// for exception handler base
pub const ON_CHIP_ADDR: GuestAddr = 0x100;

pub struct ExceptionHandler {
    exception_vector_base: GuestAddr,
    #[allow(dead_code)]
    exception_addr_reset: GuestAddr,
    exception_addr_undef: GuestAddr,
    exception_addr_svc: GuestAddr,
    exception_addr_preab: GuestAddr,
    exception_addr_datab: GuestAddr,
    exception_addr_hyp: GuestAddr,
    exception_addr_irq: GuestAddr,
    exception_addr_fiq: GuestAddr,
    hook_ids: Vec<InstructionHookId>,
}

static mut EXCEPTION_VECTOR_BASE: GuestAddr = 0;

impl Default for ExceptionHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ExceptionHandler {
    pub fn new() -> Self {
        let exception_vector_base = ON_CHIP_ADDR;
        Self {
            exception_vector_base,
            exception_addr_reset: exception_vector_base + 4 * (ExceptionType::RESET as u32),
            exception_addr_undef: exception_vector_base + 4 * (ExceptionType::UNDEF as u32),
            exception_addr_svc: exception_vector_base + 4 * (ExceptionType::SVC as u32),
            exception_addr_preab: exception_vector_base + 4 * (ExceptionType::PREAB as u32),
            exception_addr_datab: exception_vector_base + 4 * (ExceptionType::DATAB as u32),
            exception_addr_hyp: exception_vector_base + 4 * (ExceptionType::HYP as u32),
            exception_addr_irq: exception_vector_base + 4 * (ExceptionType::IRQ as u32),
            exception_addr_fiq: exception_vector_base + 4 * (ExceptionType::FIQ as u32),
            hook_ids: vec![],
        }
    }
    pub fn is_exception_handler_addr(addr: &GuestAddr) -> bool {
        (ON_CHIP_ADDR..(ON_CHIP_ADDR + 4 * ExceptionType::UNKNOWN as u32)).contains(addr)
    }
    pub fn start(&mut self, emu: &Qemu) {
        unsafe { EXCEPTION_VECTOR_BASE = self.exception_vector_base };
        //emu.set_hook(self.exception_addr_reset, exception_hook, emu as *const _ as u64, false);
        self.hook_ids.push(emu.set_hook(
            emu as *const _ as u64,
            self.exception_addr_undef,
            exception_hook,
            false,
        ));
        self.hook_ids.push(emu.set_hook(
            emu as *const _ as u64,
            self.exception_addr_svc,
            exception_hook,
            false,
        ));
        self.hook_ids.push(emu.set_hook(
            emu as *const _ as u64,
            self.exception_addr_preab,
            exception_hook,
            false,
        ));
        self.hook_ids.push(emu.set_hook(
            emu as *const _ as u64,
            self.exception_addr_datab,
            exception_hook,
            false,
        ));
        self.hook_ids.push(emu.set_hook(
            emu as *const _ as u64,
            self.exception_addr_hyp,
            exception_hook,
            false,
        ));
        self.hook_ids.push(emu.set_hook(
            emu as *const _ as u64,
            self.exception_addr_irq,
            exception_hook,
            false,
        ));
        self.hook_ids.push(emu.set_hook(
            emu as *const _ as u64,
            self.exception_addr_fiq,
            exception_hook,
            false,
        ));
    }

    pub fn stop(&self) {
        for &hook_id in &self.hook_ids {
            hook_id.remove(true);
        }
    }
}

extern "C" fn exception_hook(data: u64, pc: GuestAddr) {
    match ((pc - unsafe { EXCEPTION_VECTOR_BASE }) / 4).into() {
        ExceptionType::RESET => unsafe { HOOK_TRIGGERED |= 1 << ExceptionType::RESET as u8 },
        ExceptionType::UNDEF => unsafe { HOOK_TRIGGERED |= 1 << ExceptionType::UNDEF as u8 },
        // ExceptionType::SVC => unsafe { HOOK_TRIGGERED |= 1 << ExceptionType::SVC as u8 },
        ExceptionType::SVC => return,
        ExceptionType::PREAB => unsafe { HOOK_TRIGGERED |= 1 << ExceptionType::PREAB as u8 },
        ExceptionType::DATAB => unsafe { HOOK_TRIGGERED |= 1 << ExceptionType::DATAB as u8 },
        //ExceptionType::DATAB => log::info!("Data abort triggered"),
        ExceptionType::HYP => unsafe { HOOK_TRIGGERED |= 1 << ExceptionType::HYP as u8 },
        ExceptionType::IRQ => unsafe { HOOK_TRIGGERED |= 1 << ExceptionType::IRQ as u8 },
        ExceptionType::FIQ => unsafe { HOOK_TRIGGERED |= 1 << ExceptionType::FIQ as u8 },
        _ => log::error!("Unknown exception triggered"),
    }
    let emu = unsafe { (data as *const Qemu).as_ref().unwrap() };
    log::debug!("Exception hook: pc={:#x}", pc);
    match ((pc - unsafe { EXCEPTION_VECTOR_BASE }) / 4).into() {
        ExceptionType::RESET => log::debug!("Exception: RESET"),
        ExceptionType::UNDEF => {
            let sp: u32 = emu.read_reg(Regs::Sp).unwrap();
            let lr: u32 = emu.read_reg(Regs::Lr).unwrap();
            log::debug!("Exception: UNDEF sp_undef: {sp:#x} lr_undef: {lr:#x}");
        }
        ExceptionType::SVC => log::debug!("Exception: SVC"),
        ExceptionType::PREAB => log::debug!("Exception: PREAB"),
        ExceptionType::DATAB => {
            let sp: u32 = emu.read_reg(Regs::Sp).unwrap();
            let lr: u32 = emu.read_reg(Regs::Lr).unwrap();
            log::debug!("Exception: DATAAB sp_undef: {sp:#x} lr_undef: {lr:#x}");
        }
        ExceptionType::HYP => log::debug!("Exception: HYP"),
        ExceptionType::IRQ => log::debug!("Exception: IRQ"),
        ExceptionType::FIQ => log::debug!("Exception: FIQ"),
        _ => log::error!("Unknown exception triggered"),
    }

    emu.current_cpu().unwrap().trigger_breakpoint();
}

static mut HOOK_TRIGGERED: usize = 0;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExceptionFeedback {}

impl<S> Feedback<S> for ExceptionFeedback
where
    S: UsesInput + State,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer,
        OT: ObserversTuple<S>,
    {
        unsafe {
            if HOOK_TRIGGERED != 0 {
                log::info!("ExceptionFeedback=True");
                HOOK_TRIGGERED = 0;
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }
}

impl Named for ExceptionFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ExceptionFeedback")
    }
}

impl ExceptionFeedback {
    /// Creates a new [`ExceptionFeedback`]
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for ExceptionFeedback {
    fn default() -> Self {
        Self::new()
    }
}
