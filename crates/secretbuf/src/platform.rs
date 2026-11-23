use std::ptr::NonNull;

#[cfg(any(unix, windows))]
pub(crate) fn page_size() -> usize {
    use std::sync::OnceLock;
    static SIZE: OnceLock<usize> = OnceLock::new();
    *SIZE.get_or_init(|| {
        let size = os_page_size();
        if size.is_power_of_two() { size } else { 4096 }
    })
}

#[cfg(unix)]
fn os_page_size() -> usize {
    // SAFETY: sysconf accepts the constant selector and no pointer arguments.
    usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(0)
}

#[cfg(windows)]
fn os_page_size() -> usize {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    let mut info = std::mem::MaybeUninit::<SYSTEM_INFO>::uninit();
    // SAFETY: GetSystemInfo initializes the provided SYSTEM_INFO buffer.
    unsafe {
        GetSystemInfo(info.as_mut_ptr());
        info.assume_init().dwPageSize as usize
    }
}

#[cfg(unix)]
pub(crate) fn lock(pointer: NonNull<u8>, len: usize) -> bool {
    // SAFETY: callers provide a live, exclusively owned, page-sized allocation.
    unsafe { libc::mlock(pointer.as_ptr().cast(), len) == 0 }
}

#[cfg(unix)]
pub(crate) fn unlock(pointer: NonNull<u8>, len: usize) {
    // SAFETY: this allocation has been locked and has not been freed.
    unsafe { libc::munlock(pointer.as_ptr().cast(), len) };
}

#[cfg(windows)]
pub(crate) fn lock(pointer: NonNull<u8>, len: usize) -> bool {
    use windows_sys::Win32::System::Memory::VirtualLock;
    // SAFETY: callers provide a live, exclusively owned, page-sized allocation.
    unsafe { VirtualLock(pointer.as_ptr().cast(), len) != 0 }
}

#[cfg(windows)]
pub(crate) fn unlock(pointer: NonNull<u8>, len: usize) {
    use windows_sys::Win32::System::Memory::VirtualUnlock;
    // SAFETY: this allocation has been locked and has not been freed.
    unsafe { VirtualUnlock(pointer.as_ptr().cast(), len) };
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn page_size() -> usize {
    1
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn lock(_: NonNull<u8>, _: usize) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn unlock(_: NonNull<u8>, _: usize) {}
