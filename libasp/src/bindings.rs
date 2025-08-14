//! This module contains all the custom hooks
//! that we are exposing in addition to the `LibAFL` accessors
//!

use libafl::Error;
use libafl_bolts::impl_serdeany;
use libafl_qemu::{
    sys::{hwaddr, vaddr, GuestPhysAddr},
    GuestAddr, QemuError, CPU,
};
use serde::{Deserialize, Serialize};

// These need to be kept in sync with the functions in the emulator repository
extern "C" {
    fn aspfuzz_write_smn_flash(addr: hwaddr, len: hwaddr, buf: *mut u8);
    fn aspfuzz_x86_write(addr: hwaddr, buf: *mut u8, len: hwaddr) -> i32;
    fn aspfuzz_x86_read(addr: hwaddr, buf: *mut u8, len: hwaddr) -> i32;
    fn aspfuzz_access_observer_activate(addr: hwaddr, size: hwaddr) -> i32;
    fn aspfuzz_access_observer_reset() -> i32;
    /// This is a little tricky to use because we will always just write back
    /// the value in our current struct, so we need to treat 0 as a special case
    fn aspfuzz_access_observer_status(get_read: bool, addr: *mut hwaddr, pc: *mut vaddr) -> i32;
}
/// # Safety
/// This function should only be called if QEMU has been fully initialized
/// and the flash memory is accessible
pub unsafe fn write_flash_mem(addr: GuestAddr, buf: &[u8]) {
    aspfuzz_write_smn_flash(
        addr.into(),
        buf.len().try_into().unwrap(),
        buf.as_ptr().cast_mut(),
    );
}

/// Provide the CPU as proof that QEMU has been initialized and is halted
pub fn write_x86_mem(_cpu: &CPU, addr: GuestPhysAddr, buf: &[u8]) -> Result<(), Error> {
    let i;
    unsafe {
        i = aspfuzz_x86_write(
            addr.into(),
            buf.as_ptr().cast_mut(),
            buf.len().try_into().unwrap(),
        );
    }
    if i == 0 {
        Ok(())
    } else {
        Err(Error::illegal_state("Failed to write to x86 memory"))
    }
}

pub fn read_x86_mem(
    _cpu: &CPU,
    addr: GuestPhysAddr,
    buf: &mut [u8],
    len: GuestPhysAddr,
) -> Result<(), Error> {
    let i = unsafe { aspfuzz_x86_read(addr, buf.as_mut_ptr(), len) };
    if i == 0 {
        Ok(())
    } else {
        Err(Error::illegal_state("Failed to read from x86 memory"))
    }
}

const MAILBOX_BASE_ADDR: GuestAddr = 0x03010570;

/// Provide the CPU as proof that QEMU has been initialized and is halted
pub fn write_mailbox_value(cpu: &CPU, values: MailboxValues) -> Result<(), Error> {
    cpu.write_mem(MAILBOX_BASE_ADDR, &values.mbox.to_le_bytes())
        .map_err(QemuError::RW)?;
    cpu.write_mem(MAILBOX_BASE_ADDR + 4, &values.ptr_lower.to_le_bytes())
        .map_err(QemuError::RW)?;
    cpu.write_mem(MAILBOX_BASE_ADDR + 8, &values.ptr_higher.to_le_bytes())
        .map_err(QemuError::RW)?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct MailboxValues {
    pub mbox: u32,
    pub ptr_lower: u32,
    pub ptr_higher: u32,
}
impl_serdeany!(MailboxValues);

pub fn read_mailbox_value(cpu: &CPU) -> Result<MailboxValues, Error> {
    let mut buf = [0u8; 4 * 3];
    cpu.read_mem(MAILBOX_BASE_ADDR, &mut buf)
        .map_err(QemuError::RW)?;
    let mbox = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let ptr_lower = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let ptr_higher = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    Ok(MailboxValues {
        mbox,
        ptr_lower,
        ptr_higher,
    })
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccessObserver {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessObserverMetadata {
    pub caught_read: Option<(hwaddr, vaddr)>,
    pub caught_write: Option<(hwaddr, vaddr)>,
}

impl_serdeany!(AccessObserverMetadata);
impl AccessObserver {
    pub fn activate(&self, addr: hwaddr, size: hwaddr) -> Result<(), Error> {
        let rc;
        unsafe {
            rc = aspfuzz_access_observer_activate(addr, size);
        }
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::illegal_state("Failed to activate write catcher"))
        }
    }
    pub fn reset(&self) -> Result<(), Error> {
        let rc;
        unsafe {
            rc = aspfuzz_access_observer_reset();
        }
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::illegal_state("Failed to reset write catcher"))
        }
    }

    pub fn status(&self) -> Result<AccessObserverMetadata, Error> {
        let accessor = |is_read: bool| -> Result<Option<(_, _)>, Error> {
            let mut addr: hwaddr = 0;
            let mut pc = 0;
            let rc;
            unsafe {
                rc = aspfuzz_access_observer_status(is_read, &mut addr, &mut pc);
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

        Ok(AccessObserverMetadata {
            caught_read: read,
            caught_write: write,
        })
    }
}
