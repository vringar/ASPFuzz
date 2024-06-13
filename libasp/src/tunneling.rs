use libafl::inputs::UsesInput;
use libafl_qemu::*;
use log;

use crate::YAMLConfig;

pub fn setup_tunnels<QT,S>(hooks: &QemuHooks<QT,S>, config: &YAMLConfig) where QT: QemuHelperTuple<S>, S:UsesInput{
    for (addr, action) in &config.tunnels_cmps {
        let addr = *addr;
        if let Ok(constant) = action.parse::<GuestReg>() {
            hooks.instruction(addr, Hook::Closure(Box::new(move |hks: &mut QemuHooks<QT,S>, _state, _unkown| {
                log::debug!("Tunnel - Constant [{:#x}, {}]", addr, constant);
                hks.qemu().write_reg(Regs::R0, constant).unwrap();
            })), false)
        } else {
            let source_register = str_reg_to_regs(action).unwrap();
            let action = action.clone();
            hooks.instruction(addr, Hook::Closure(Box::new(move |hks: &mut QemuHooks<QT,S>, _state, _unknown| {
                log::debug!("Tunnel - Register [{:#x}, {}]", addr, action);

                let r0: u32 = hks.qemu().read_reg(source_register).unwrap();
                hks.qemu().write_reg(Regs::R0, r0).unwrap();
            })), false)
        };
    }
}

/// As we do not own the Regs type this is the best we can do
pub fn str_reg_to_regs(reg: &str) -> Option<Regs> {
    Some(match reg {
        "R0" => Regs::R0,
        "R1" => Regs::R1,
        "R2" => Regs::R2,
        "R3" => Regs::R3,
        "R4" => Regs::R4,
        "R5" => Regs::R5,
        "R6" => Regs::R6,
        "R7" => Regs::R7,
        "R8" => Regs::R8,
        "R9" => Regs::R9,
        "R10" => Regs::R10,
        "R11" => Regs::R11,
        "R12" => Regs::R12,
        "R13" => Regs::R13,
        "R14" => Regs::R14,
        "R15" => Regs::R15,
        "R25" => Regs::R25,
        "Sp" => Regs::Sp,
        "SP" => Regs::Sp,
        "Lr" => Regs::Lr,
        "LR" => Regs::Lr,
        "Pc" => Regs::Pc,
        "PC" => Regs::Pc,
        "Sb" => Regs::Sb,
        "SB" => Regs::Sb,
        "Sl" => Regs::Sl,
        "SL" => Regs::Sl,
        "Fp" => Regs::Fp,
        "FP" => Regs::Fp,
        "Ip" => Regs::Ip,
        "IP" => Regs::Ip,
        "Cpsr" => Regs::Cpsr,
        "CPSR" => Regs::Cpsr,
        _ => return None,
    })
}
