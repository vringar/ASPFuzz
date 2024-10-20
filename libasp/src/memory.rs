use libafl::Error;
use libafl_qemu::{GuestAddr, CPU};

extern "C" {
    fn aspfuzz_write_smn_flash(addr: GuestAddr, len: i32, buf: *mut u8);
    fn aspfuzz_x86_write(addr: GuestAddr, buf: *mut u8, len: i32) -> i32;
    fn update_mailbox(mbox: u32, ptr_lower: u32, ptr_higher: u32) -> u32;
    fn read_mailbox(mbox: *mut u32, ptr_lower: *mut u32, ptr_higher: *mut u32) -> u32;

}
/// # Safety
/// This function should only be called if QEMU has been fully initialized
/// and the flash memory is accessible
pub unsafe fn write_flash_mem(addr: GuestAddr, buf: &[u8]) {
    aspfuzz_write_smn_flash(addr, buf.len() as i32, buf.as_ptr() as *mut u8);
}
/// Provide the CPU as proof that QEMU has been initialized and is halted
pub fn write_x86_mem(_cpu: &CPU, addr: GuestAddr, buf: &[u8]) -> Result<(), Error> {
    let i;
    unsafe {
        i = aspfuzz_x86_write(addr, buf.as_ptr() as *mut u8, buf.len() as i32);
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
pub fn read_mailbox_value(_cpu: &CPU) -> Result<[u32; 3], Error> {
    let mut mbox: u32 = 0;
    let mut ptr_lower: u32 = 0;
    let mut ptr_higher: u32 = 0;
    let rc;
    unsafe {
        rc = read_mailbox(&mut mbox, &mut ptr_lower, &mut ptr_higher);
    }
    if rc == 0 {
        Ok([mbox, ptr_lower, ptr_higher])
    } else {
        Err(Error::illegal_state("Failed to read mailbox"))
    }
}
