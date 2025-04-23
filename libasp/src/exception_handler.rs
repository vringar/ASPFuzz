use libafl::prelude::*;
/// Catching and handling ARM CPU exceptions durign the test-case execution
use libafl_qemu::{
    modules::{EmulatorModule, EmulatorModuleTuple},
    EmulatorModules, Hook, HookId, InstructionHookId, Qemu,
};
use strum::{EnumIter, FromRepr, IntoEnumIterator};

use core::fmt::Debug;
use libafl_bolts::Named;
use log;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::RegisterMetadata;

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Debug, FromRepr, EnumIter)]
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

#[derive(Debug)]
pub struct ExceptionModule {
    hook_ids: Vec<InstructionHookId>,
    // execption_vector_base: GuestAddr,
    //cs: Capstone,
}

impl Default for ExceptionModule {
    fn default() -> Self {
        Self::new()
    }
}

impl ExceptionModule {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hook_ids: vec![],
            // execption_vector_base: 0x0,
            //cs: capstone().detail(true).build().unwrap(),
        }
    }

    pub fn update_exception_vector_base<ET, I, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        S: Unpin + HasMetadata,
        I: Unpin,
    {
        for &hook_id in &self.hook_ids {
            hook_id.remove(true);
        }
        self.hook_ids.clear();

        for enum_value in ExceptionType::iter() {
            // This is fine as long as we don't reach the tOS
            let exception_addr = 0x100 + 4 * (enum_value as u32);
            if enum_value == ExceptionType::RESET || enum_value == ExceptionType::SVC {
                continue;
            }
            emulator_modules.instructions(
                exception_addr,
                Hook::Closure(Box::new(
                    move |qemu: Qemu,
                          _: &mut EmulatorModules<ET, I, S>,
                          state: Option<&mut S>,
                          _pc| {
                        let state =
                            state.expect("State should be present when an exception is triggered");
                        let exception_meta = ExceptionHandlerMetadata {
                            triggered_exception: enum_value,
                            registers: RegisterMetadata::new(qemu),
                        };
                        state.metadata_map_mut().insert(exception_meta);
                        qemu.current_cpu().unwrap().trigger_breakpoint();
                    },
                )),
                true,
            );
        }
    }

    // When this block hook is set it completely freezes on startup
    // However, this would be the correct way to set a hook on the vector table changing
    // Inspired by libafl_qemu/src/modules/call.rs
    // fn hook_vbar_writes<ET, S>(
    //     emulator_modules: &mut EmulatorModules<ET, I, S>,
    //     _state: Option<&mut S>,
    //     pc: GuestAddr,
    // ) -> Option<u64>
    // where
    //     ET: EmulatorModuleTuple<I,S>,
    //     S: Unpin + HasMetadata,
    // {
    //     todo!("hook_vbar_writes is not working, it freezes the emulator on startup");
    // if let Some(h) = emulator_modules.get_mut::<Self>() {
    //     h.cs.set_mode(if pc & 1 == 1 {
    //         arch::arm::ArchMode::Thumb.into()
    //     } else {
    //         arch::arm::ArchMode::Arm.into()
    //     })
    //     .unwrap();
    // }

    // let qemu = emulator_modules.qemu();
    // if let Some(h) = emulator_modules.modules().match_first_type::<Self>() {
    //     let code = &mut [0; 512];
    //     unsafe { qemu.read_mem(pc, code) };
    //     let mut iaddr = pc;

    //     'disasm: while let Ok(insns) = h.cs.disasm_count(code, iaddr.into(), 1) {
    //         if insns.is_empty() {
    //             break;
    //         }
    //         let insn = insns.first().unwrap();
    //         let insn_detail: InsnDetail = h.cs.insn_detail(insn).unwrap();
    //         for detail in insn_detail.groups() {
    //             match u32::from(detail.0) {
    //                 // Anything that gets us out of the block makes the rest of the block irrelevant
    //                 capstone::InsnGroupType::CS_GRP_RET
    //                 | capstone::InsnGroupType::CS_GRP_INVALID
    //                 | capstone::InsnGroupType::CS_GRP_JUMP
    //                 | capstone::InsnGroupType::CS_GRP_IRET
    //                 |  => {
    //                     break 'disasm;
    //                 }
    //                 capstone::InsnGroupType::CS_GRP_PRIVILEGE => {}
    //                 _ => {continue 'disasm;}
    //             }
    //         }
    //         if insn.mnemonic().unwrap() == "MCR" {
    //             log::error!(
    //                 "MCR instruction found, operands are {:?}",
    //                 insn.op_str().unwrap()
    //             );
    //         }
    //         iaddr += insn.bytes().len() as GuestAddr;

    //         unsafe {
    //             qemu.read_mem(pc, code);
    //         }
    //     }
    // }
    // None
    //}
}

impl<I, S> EmulatorModule<I, S> for ExceptionModule
where
    S: Unpin + HasMetadata,
    I: Unpin,
{
    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, _emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: EmulatorModuleTuple<I, S>,
    {
        // TODO: figure out why this is so slow
        // emulator_modules.blocks(
        //     Hook::Function(Self::hook_vbar_writes),
        //     Hook::Empty,
        //     Hook::Empty,
        // );
    }
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        self.update_exception_vector_base(emulator_modules);
    }

    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: &mut S,
        _input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        // THIS IS REQUIRED
        let _ = state
            .metadata_map_mut()
            .remove::<ExceptionHandlerMetadata>();
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]

struct ExceptionHandlerMetadata {
    triggered_exception: ExceptionType,
    registers: RegisterMetadata,
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
        let meta: Option<&ExceptionHandlerMetadata> = state.metadata_map_mut().get();
        if meta.is_some() {
            log::info!("ExceptionFeedback=True");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        let meta: Option<&ExceptionHandlerMetadata> = state.metadata_map_mut().get();
        if let Some(meta) = meta {
            testcase.add_metadata(meta.clone());
        }
        Ok(())
    }
}

impl Named for ExceptionFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ExceptionFeedback")
    }
}
