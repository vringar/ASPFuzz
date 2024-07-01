use libafl_qemu::GuestAddr;

extern "C" {
    fn aspfuzz_write_smn_flash(addr: GuestAddr, len: i32, buf: *mut u8);
}
pub unsafe fn write_flash_mem(addr: GuestAddr, buf: &[u8]) {
    aspfuzz_write_smn_flash(addr, buf.len() as i32, buf.as_ptr() as *mut u8);
}
