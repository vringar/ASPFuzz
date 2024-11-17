//! This module defines multiple crash detection hooks

use std::ptr::addr_of_mut;

use libafl::{inputs::UsesInput, HasMetadata};
use libafl_qemu::{
    modules::{
        EmulatorModule, EmulatorModuleTuple, NopAddressFilter, NopPageFilter, NOP_ADDRESS_FILTER,
        NOP_PAGE_FILTER,
    },
    sys::TCGTemp,
    EmulatorModules, GuestAddr, Hook, MemAccessInfo, Regs,
};
use serde::Deserialize;

use super::write_catcher::WriteCatcherConfig;

#[derive(Clone, Deserialize, Debug)]
pub struct NoExecConfig {
    begin: GuestAddr,
    end: GuestAddr,
}

#[derive(Clone, Deserialize, Debug)]
pub struct ForbiddenWritesConfig {
    begin: GuestAddr,
    end: GuestAddr,
    /// A list of PCs that are allowed to write to this region
    #[serde(default)]
    no_hook: Vec<GuestAddr>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct MmapConfig {
    no_exec: Vec<NoExecConfig>,
    ccp_memcopy_addr: GuestAddr,
    /// A list of addresses memcopy is not allowed to write to
    forbidden_memcopies: Vec<ForbiddenWritesConfig>,
    forbidden_writes: Vec<ForbiddenWritesConfig>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct CrashConfig {
    breakpoints: Vec<GuestAddr>,
    mmap: MmapConfig,
    pub x86: Option<WriteCatcherConfig>,
}

/// This can't be actual metadata because we are setting it
/// in `init_module` and we can't access the state in the hooks
/// so we need to store it in the module
#[derive(Debug, Default)]
struct CrashRuntimeConfig {
    counter_write_hooks: u64,
    counter_edge_hooks: u64,
    ccp_memcopy_id: u64,
}

#[derive(Debug)]
pub struct CrashModule {
    c: CrashConfig,
    r: CrashRuntimeConfig,
}

impl CrashModule {
    pub fn new(conf: CrashConfig) -> Self {
        CrashModule {
            c: conf,
            r: CrashRuntimeConfig::default(),
        }
    }
}

impl<S> EmulatorModule<S> for CrashModule
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

    fn init_module<ET>(&self, modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        self.c.breakpoints.iter().for_each(|bp| {
            modules.qemu().set_breakpoint(*bp);
        });
        // Block hooks and write hooks for crash detection
        modules.blocks(
            Hook::Function(gen_block_hook),
            Hook::Empty,
            Hook::Function(exec_block_hook),
        );
        if !self.c.mmap.forbidden_writes.is_empty() {
            log::debug!("Adding write generation hooks");
            modules.writes(
                Hook::Function(gen_writes_hook),
                Hook::Function(exec_writes_hook),
                Hook::Function(exec_writes_hook),
                Hook::Function(exec_writes_hook),
                Hook::Function(exec_writes_hook),
                Hook::Function(exec_writes_hook_n),
            );
        } else {
            log::debug!("No write generation hooks");
        }
    }
}

fn gen_block_hook<ET, S>(
    modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    src: GuestAddr,
) -> Option<u64>
where
    S: UsesInput + Unpin + HasMetadata,
    ET: EmulatorModuleTuple<S>,
{
    let module: &mut CrashModule = modules
        .modules_mut()
        .match_first_type_mut()
        .expect("This should only run with a FlashHookConfig");
    let runtime_config = &mut module.r;
    let id = runtime_config.counter_edge_hooks;
    runtime_config.counter_edge_hooks += 1;
    for no_exec in module.c.mmap.no_exec.iter() {
        if src >= no_exec.begin && src < no_exec.end {
            log::debug!("Generate block:");
            log::debug!("> src: {:#x}", src);
            log::debug!("> id: {:#x}", id);
            modules.qemu().current_cpu().unwrap().trigger_breakpoint();
            return Some(id);
        }
    }

    if !module.c.mmap.forbidden_memcopies.is_empty() && module.c.mmap.ccp_memcopy_addr == src {
        log::debug!("Adding block hook for ccp_memcopy_addr");
        runtime_config.ccp_memcopy_id = id;
        return Some(id);
    }
    None
}
fn exec_block_hook<ET, S>(modules: &mut EmulatorModules<ET, S>, _state: Option<&mut S>, id: u64)
where
    S: UsesInput + Unpin + HasMetadata,
    ET: EmulatorModuleTuple<S>,
{
    let emu = modules.qemu();
    let module: &CrashModule = modules
        .modules()
        .match_first_type()
        .expect("This should only run with a FlashHookConfig");
    if !module.r.ccp_memcopy_id == id {
        log::debug!("Execute block: id: {id}");
        // log::debug!("> data: {}", (todo!() as u32));
        emu.current_cpu().unwrap().trigger_breakpoint();
        return;
    }
    let cpu = emu.current_cpu().unwrap();
    let pc: u64 = cpu.read_reg(Regs::Pc).unwrap();
    assert_eq!(pc as GuestAddr, module.c.mmap.ccp_memcopy_addr);
    let cpy_src: GuestAddr = cpu.read_reg::<libafl_qemu::Regs, u64>(Regs::R0).unwrap() as GuestAddr;
    let cpy_dest_start: GuestAddr =
        cpu.read_reg::<libafl_qemu::Regs, u64>(Regs::R1).unwrap() as GuestAddr;
    let cpy_len: GuestAddr = cpu.read_reg::<libafl_qemu::Regs, u64>(Regs::R2).unwrap() as GuestAddr;
    let cpy_dest_end: GuestAddr = cpy_dest_start + cpy_len;
    log::debug!(
        "Flash read fn from {:#010x} to {:#010x} for {:#x} bytes",
        cpy_src,
        cpy_dest_start,
        cpy_len
    );
    for area in &module.c.mmap.forbidden_memcopies {
        if (area.begin >= cpy_dest_start && area.begin < cpy_dest_end)
            || (area.end >= cpy_dest_start && area.end < cpy_dest_end)
        {
            let cpy_lr: GuestAddr =
                cpu.read_reg::<libafl_qemu::Regs, u64>(Regs::Lr).unwrap() as GuestAddr;
            log::debug!(
                "Flash read fn writes to [{:#010x}, {:#010x}] from function {cpy_lr:#010x}",
                area.begin,
                area.end
            );
            if !area.no_hook.contains(&cpy_lr) {
                log::info!("Flash read fn hook triggered!");
                cpu.trigger_breakpoint();
            }
        }
    }
}

fn gen_writes_hook<ET, S>(
    modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    _: *mut TCGTemp,
    mem_acces_info: MemAccessInfo,
) -> Option<u64>
where
    S: UsesInput + Unpin + HasMetadata,
    ET: EmulatorModuleTuple<S>,
{
    let module: &mut CrashModule = modules
        .modules_mut()
        .match_first_type_mut()
        .expect("This should only run with a FlashHookConfig");

    let runtime_conf = &mut module.r;
    // TODO: for known write locations at "compile" time
    // Don't emit hooks if they are outside of range
    for ForbiddenWritesConfig {
        no_hook: no_write, ..
    } in module.c.mmap.forbidden_writes.iter()
    {
        for no_ldr in no_write {
            if pc == *no_ldr {
                log::debug!("Skipping generation hook for {:#010x}", pc);
                return None;
            }
        }
    }
    let size = mem_acces_info.size();
    let hook_id = runtime_conf.counter_write_hooks;
    runtime_conf.counter_write_hooks += 1;
    log::debug!("Generate writes:  id: {hook_id:#x}  src: {pc:#x} size: {size}");
    Some(hook_id)
}

fn exec_writes_hook<ET, S>(
    modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    id: u64,
    addr: GuestAddr,
) where
    S: UsesInput + Unpin + HasMetadata,
    ET: EmulatorModuleTuple<S>,
{
    let module: &CrashModule = modules
        .modules()
        .match_first_type()
        .expect("This should only run with a FlashHookConfig");
    for &ForbiddenWritesConfig { begin, end, .. } in module.c.mmap.forbidden_writes.iter() {
        if addr >= begin && addr < end {
            log::debug!("Execute writes: id: {id:#x} addr: {addr:#x}");
            // log::debug!("> data: {}", todo!() as u64);
            let emu = modules.qemu();
            emu.current_cpu().unwrap().trigger_breakpoint();
        }
    }
}
fn exec_writes_hook_n<ET: EmulatorModuleTuple<S>, S: UsesInput>(
    modules: &mut EmulatorModules<ET, S>,
    _input: Option<&mut S>,
    id: u64,
    addr: u32,
    size: usize,
) {
    let module: &CrashModule = modules
        .modules()
        .match_first_type()
        .expect("This should only run with a FlashHookConfig");
    for no_write in module.c.mmap.forbidden_writes.iter() {
        if addr >= no_write.begin && addr < no_write.end {
            log::debug!("Execute writes: id: {id:#x}, addr: {addr:#x}, size: {size}");
            // log::debug!("> data: {}", (todo!() as u32));
            modules.qemu().current_cpu().unwrap().trigger_breakpoint();
        }
    }
}
