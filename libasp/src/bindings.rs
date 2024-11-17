//! This module contains all the custom hooks
//! that we are exposing in addition to the LibAFL accessors
//!

use libafl::Error;
use libafl_bolts::impl_serdeany;
use libafl_qemu::{
    sys::{hwaddr, vaddr, CPUStatePtr},
    GuestAddr, CPU,
};
use serde::{Deserialize, Serialize};

// These need to be kept in sync with the functions in the emulator repository
extern "C" {
    fn aspfuzz_write_smn_flash(addr: hwaddr, len: hwaddr, buf: *mut u8);
    fn aspfuzz_x86_write(addr: hwaddr, buf: *mut u8, len: hwaddr) -> i32;
    fn update_mailbox(mbox: u32, ptr_lower: u32, ptr_higher: u32) -> i32;
    fn read_mailbox(mbox: *mut u32, ptr_lower: *mut u32, ptr_higher: *mut u32) -> i32;
    fn aspfuzz_write_catcher_activate(addr: hwaddr, size: hwaddr) -> i32;
    fn aspfuzz_write_catcher_reset() -> i32;
    /// This is a little tricky to use because we will always just write back
    /// the value in our current struct, so we need to treat 0 as a special case
    fn aspfuzz_write_catcher_status(get_read: bool, addr: *mut hwaddr, pc: *mut vaddr) -> i32;
    fn set_pc(cpu: CPUStatePtr, new_pc: vaddr) -> i32;
}
/// # Safety
/// This function should only be called if QEMU has been fully initialized
/// and the flash memory is accessible
pub unsafe fn write_flash_mem(addr: GuestAddr, buf: &[u8]) {
    aspfuzz_write_smn_flash(
        addr.into(),
        buf.len().try_into().unwrap(),
        buf.as_ptr() as *mut u8,
    );
}

/// Provide the CPU as proof that QEMU has been initialized and is halted
pub fn write_x86_mem(_cpu: &CPU, addr: GuestAddr, buf: &[u8]) -> Result<(), Error> {
    let i;
    unsafe {
        i = aspfuzz_x86_write(
            addr.into(),
            buf.as_ptr() as *mut u8,
            buf.len().try_into().unwrap(),
        );
    }
    if i == 0 {
        Ok(())
    } else {
        Err(Error::illegal_state("Failed to write to x86 memory"))
    }
}

/// Provide the CPU as proof that QEMU has been initialized and is halted
pub fn write_mailbox_value(
    _cpu: &CPU,
    mbox: u32,
    ptr_lower: u32,
    ptr_higher: u32,
) -> Result<(), Error> {
    let rc;
    unsafe {
        rc = update_mailbox(mbox, ptr_lower, ptr_higher);
    }
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::illegal_state("Failed to update mailbox"))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct MailboxValues {
    pub mbox: u32,
    pub ptr_lower: u32,
    pub ptr_higher: u32,
}
impl_serdeany!(MailboxValues);

pub fn read_mailbox_value(_cpu: &CPU) -> Result<MailboxValues, Error> {
    let mut mbox = MailboxValues::default();
    let rc;
    unsafe {
        rc = read_mailbox(&mut mbox.mbox, &mut mbox.ptr_lower, &mut mbox.ptr_higher);
    }
    if rc == 0 {
        Ok(mbox)
    } else {
        Err(Error::illegal_state("Failed to read mailbox"))
    }
}

pub fn cpu_set_pc(cpu: CPU, new_pc: vaddr) -> Result<(), Error> {
    let rc;
    unsafe {
        rc = set_pc(cpu.raw_ptr(), new_pc);
    }
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::illegal_state("Failed to set PC"))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WriteCatcher {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteCatcherMetadata {
    pub caught_read: Option<(hwaddr, vaddr)>,
    pub caught_write: Option<(hwaddr, vaddr)>,
}

impl_serdeany!(WriteCatcherMetadata);
impl WriteCatcher {
    pub fn write_catcher_activate(&self, addr: hwaddr, size: hwaddr) -> Result<(), Error> {
        let rc;
        unsafe {
            rc = aspfuzz_write_catcher_activate(addr, size);
        }
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::illegal_state("Failed to activate write catcher"))
        }
    }
    pub fn write_catcher_reset(&self) -> Result<(), Error> {
        let rc;
        unsafe {
            rc = aspfuzz_write_catcher_reset();
        }
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::illegal_state("Failed to reset write catcher"))
        }
    }

    pub fn write_catcher_status(&self) -> Result<WriteCatcherMetadata, Error> {
        let accessor = |is_read: bool| -> Result<Option<(_, _)>, Error> {
            let mut addr: hwaddr = 0;
            let mut pc = 0;
            let rc;
            unsafe {
                rc = aspfuzz_write_catcher_status(is_read, &mut addr, &mut pc);
            }
            if rc != 0 {
                return Err(Error::illegal_state("Failed to get read catcher status"));
            }
            if addr != 0 {
                Ok(Some((addr, pc)))
            } else {
                Ok(None)
            }
        };
        let read = accessor(true)?;
        let write = accessor(false)?;

        Ok(WriteCatcherMetadata {
            caught_read: read,
            caught_write: write,
        })
    }
}
