use libafl_qemu::*;
use log;

static mut TUNNELS_CMPS: Vec<(GuestAddr, String)> = vec![];

pub fn add_tunnels_cmp<QT, S, E>(addr: GuestAddr, r0: &str, emu: &Qemu) {
    let cmp = (addr, r0.to_string());
    unsafe {
        TUNNELS_CMPS.push(cmp);
    }
    emu.set_hook(emu as *const _ as u64, addr, tunnels_cmp_hook, false);
}

extern "C" fn tunnels_cmp_hook(data: u64, pc: GuestAddr) {
    log::debug!("Tunnels cmp hook: pc={:#x}", pc);
    let emu = unsafe { (data as *const Qemu).as_ref().unwrap() };
    for cmp in unsafe { TUNNELS_CMPS.iter() } {
        if cmp.0 == pc {
            log::debug!("Found matching tunnels cmp: [{:#x}, {}]", cmp.0, cmp.1);
            if cmp.1.parse::<GuestAddr>().is_ok() {
                emu.write_reg(Regs::R0, cmp.1.parse::<u32>().unwrap())
                    .unwrap();
                break;
            } else {
                let r0: u32 = emu.read_reg(str_reg_to_regs(&cmp.1)).unwrap();
                emu.write_reg(Regs::R0, r0).unwrap();
                break;
            }
        }
    }
}

pub fn str_reg_to_regs(reg: &str) -> Regs {
    match reg {
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
        _ => panic!("Cannot match to valid ARM register"),
    }
}
