use std::fmt;

use libafl::inputs::UsesInput;
use libafl_qemu::*;
use log;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};
#[derive(Deserialize, Debug)]
#[serde(tag = "action")]

pub enum CmpAction {
    CopyRegister {
        #[serde(deserialize_with = "parse_regs")]
        target: Regs,
        #[serde(deserialize_with = "parse_regs")]
        source: Regs,
    },
    SetConstant {
        #[serde(deserialize_with = "parse_regs")]
        target: Regs,
        value: GuestReg,
    },
    Jump {
        target: GuestAddr,
    },
    LogRegister {
        #[serde(deserialize_with = "parse_regs")]
        target: Regs
    }
}
#[derive(Deserialize, Debug)]
pub struct CmpConfig {
    pub addr: GuestAddr,
    #[serde(flatten)]
    pub value: CmpAction,
}

#[derive(Deserialize, Debug)]
pub struct TunnelConfig {
    pub cmps: Vec<CmpConfig>,
}

impl TunnelConfig {
    pub fn setup<QT, S>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
        S: UsesInput,
    {
        for CmpConfig {
            addr,
            value: action,
        } in &self.cmps
        {
            let addr = *addr;
            match *action {
                CmpAction::SetConstant { target, value } => hooks.instruction(
                    addr,
                    Hook::Closure(Box::new(
                        move |hks: &mut QemuHooks<QT, S>, _state, _unkown| {
                            log::debug!("Tunnel - Constant [{:#x}, {:?}, {:#x}]", addr, target, value);
                            hks.qemu().write_reg(target, value).unwrap();
                        },
                    )),
                    false,
                ),
                CmpAction::CopyRegister { target, source } => hooks.instruction(
                    addr,
                    Hook::Closure(Box::new(
                        move |hks: &mut QemuHooks<QT, S>, _state, _unknown| {
                            log::debug!("Tunnel - Register [{:#x}, {:?}, {:?}]", addr, target, source);

                            let value: u32 = hks.qemu().read_reg(source).unwrap();
                            hks.qemu().write_reg(target, value).unwrap();
                        },
                    )),
                    false,
                ),
                CmpAction::Jump { target } => hooks.instruction(
                    addr,
                    Hook::Closure(Box::new(
                        move |hks: &mut QemuHooks<QT, S>, _state, _unknown| {
                            log::debug!("Tunnel - Jump [{:#x}, {:#x}]", addr, target);

                            hks.qemu().write_reg(Regs::Ip, target).unwrap();
                        },
                    )),
                    false,
                ),
                CmpAction::LogRegister { target } => hooks.instruction(addr, Hook::Closure(Box::new(move |hks: &mut QemuHooks<QT, S>, _state, _unknown| {
                    let value: u32 = hks.qemu().read_reg(target).unwrap();
                    log::debug!("Tunnel - Log [{:#x}, {:?}, {:#x}]", addr, target, value);
                })), false)
            };
        }
    }
}

fn parse_regs<'de, D>(deserializer: D) -> Result<Regs, D::Error>
where
    D: Deserializer<'de>,
{
    struct RegisterVisitor;
    const VALUES: &[&str] = &["A valid Register name"];
    impl<'de> Visitor<'de> for RegisterVisitor {
        type Value = Regs;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("A valid Register name")
        }

        fn visit_str<E>(self, value: &str) -> Result<Regs, E>
        where
            E: de::Error,
        {
            parse_regs2(value).ok_or(de::Error::unknown_field(value, VALUES))
        }
    }
    deserializer.deserialize_str(RegisterVisitor)
}
/// As we do not own the Regs type this is the best we can do
pub fn parse_regs2(reg: &str) -> Option<Regs> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_register() {
        #[derive(Deserialize, Debug)]

        struct Test {
            #[serde(deserialize_with = "parse_regs")]
            target: Regs,
        }
        let text = "target: R0";
        let t: Test = serde_yaml::from_str(text).unwrap();
        match t.target {
            Regs::R0 => {}
            _ => panic!("Wrong Register"),
        }
    }
}
