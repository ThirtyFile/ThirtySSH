//! An owned mutable buffer that erases released bytes and can be handed to a
//! shared byte owner without copying its allocation.
#![deny(unsafe_op_in_unsafe_fn)]

mod platform;

use std::{
    alloc::{Layout, alloc_zeroed, dealloc, handle_alloc_error},
    fmt,
    io::{self, Read, Write},
    ops::{Deref, DerefMut, Index, IndexMut},
    ptr::NonNull,
    slice::{self, SliceIndex},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
pub struct SecretBuf {
    allocation: Option<Allocation>,
    len: usize,
}

struct Allocation {
    pointer: NonNull<u8>,
    layout: Layout,
    locked: bool,
}

// SAFETY: The allocation is exclusively owned, so it can move to another
// thread with its owner.
unsafe impl Send for Allocation {}
// SAFETY: Its contents can be changed only via a unique Rust borrow and are
// plain bytes, readable from any thread with a shared borrow.
unsafe impl Sync for Allocation {}

impl Allocation {
    fn new(capacity: usize) -> Self {
        Self::with_lock(capacity, platform::lock)
    }

    fn with_lock(capacity: usize, lock: impl FnOnce(NonNull<u8>, usize) -> bool) -> Self {
        let page = platform::page_size();
        let size = capacity
            .max(page)
            .checked_next_power_of_two()
            .expect("SecretBuf capacity overflow");
        let layout = Layout::from_size_align(size, page)
            .expect("SecretBuf capacity exceeds addressable memory");
        // SAFETY: the layout has nonzero size and a valid alignment.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) })
            .unwrap_or_else(|| handle_alloc_error(layout));
        let mut allocation = Self {
            pointer,
            layout,
            locked: false,
        };
        allocation.locked = lock(pointer, size);
        allocation
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: the allocation is fully initialized and this is a shared borrow.
        unsafe { slice::from_raw_parts(self.pointer.as_ptr(), self.layout.size()) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the allocation is fully initialized and uniquely borrowed.
        unsafe { slice::from_raw_parts_mut(self.pointer.as_ptr(), self.layout.size()) }
    }

    fn erase(&mut self) {
        self.bytes_mut().zeroize();
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        self.erase();
        if self.locked {
            platform::unlock(self.pointer, self.layout.size());
        }
        // SAFETY: this is the original allocation and allocator layout.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        // Allocation owns the erasure, unlock, and deallocation sequence.
        drop(self.allocation.take());
    }
}

impl SecretBuf {
    pub fn new() -> Self {
        Self::default()
    }

    /// A buffer of `len` zero bytes.
    pub fn zeroed(len: usize) -> Self {
        let mut buffer = Self::with_capacity(len);
        buffer.len = len;
        buffer
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            allocation: (capacity != 0).then(|| Allocation::new(capacity)),
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Set the length. Bytes cut off are erased, and bytes added are zero.
    pub fn resize(&mut self, size: usize) {
        if size <= self.len {
            self[size..].zeroize();
        } else if size
            > self
                .allocation
                .as_ref()
                .map_or(0, |allocation| allocation.layout.size())
        {
            let mut next = Allocation::new(size);
            next.bytes_mut()[..self.len].copy_from_slice(self);
            self.allocation = Some(next);
        }
        self.len = size;
    }

    pub fn clear(&mut self) {
        self.resize(0);
    }

    pub fn push(&mut self, value: u8) {
        self.grow(1)[0] = value;
    }

    /// Append up to `limit` bytes from one read of `reader`. Nothing the
    /// reader left behind without counting it stays in the buffer.
    pub fn fill_from(&mut self, mut reader: impl Read, limit: usize) -> io::Result<usize> {
        let start = self.len;
        match reader.read(self.grow(limit)) {
            Ok(read) if read <= limit => {
                self.resize(start + read);
                Ok(read)
            }
            result => {
                self.resize(start);
                result.and_then(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "reader returned an invalid byte count",
                    ))
                })
            }
        }
    }

    /// Lengthen the buffer by `additional` zero bytes and return them for
    /// the caller to fill in place.
    pub fn grow(&mut self, additional: usize) -> &mut [u8] {
        let old_len = self.len;
        self.resize(
            old_len
                .checked_add(additional)
                .expect("SecretBuf length overflow"),
        );
        &mut self[old_len..]
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.grow(bytes.len()).copy_from_slice(bytes);
    }
}

impl Deref for SecretBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.allocation
            .as_ref()
            .map_or(&[], |allocation| &allocation.bytes()[..self.len])
    }
}

impl DerefMut for SecretBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        match &mut self.allocation {
            Some(allocation) => &mut allocation.bytes_mut()[..self.len],
            None => &mut [],
        }
    }
}

impl AsRef<[u8]> for SecretBuf {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsMut<[u8]> for SecretBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl<I: SliceIndex<[u8]>> Index<I> for SecretBuf {
    type Output = I::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.as_ref()[index]
    }
}

impl<I: SliceIndex<[u8]>> IndexMut<I> for SecretBuf {
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.as_mut()[index]
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            formatter.write_str("<empty>")
        } else {
            write!(formatter, "<{}>", self.len)
        }
    }
}

impl Clone for SecretBuf {
    fn clone(&self) -> Self {
        Self::from(&self[..])
    }
}

impl From<&[u8]> for SecretBuf {
    fn from(bytes: &[u8]) -> Self {
        let mut buffer = Self::zeroed(bytes.len());
        buffer.copy_from_slice(bytes);
        buffer
    }
}

impl From<Vec<u8>> for SecretBuf {
    fn from(value: Vec<u8>) -> Self {
        Self::from(&Zeroizing::new(value)[..])
    }
}

impl From<String> for SecretBuf {
    fn from(value: String) -> Self {
        Self::from(value.into_bytes())
    }
}

impl From<&str> for SecretBuf {
    fn from(value: &str) -> Self {
        Self::from(value.as_bytes())
    }
}

impl Write for SecretBuf {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "ssh-encoding")]
impl ssh_encoding::Writer for SecretBuf {
    fn write(&mut self, bytes: &[u8]) -> ssh_encoding::Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shrinking_and_clearing_erase_bytes_in_the_retained_allocation() {
        let mut buffer = SecretBuf::from("fixture");
        let pointer = buffer.as_ptr();
        buffer.resize(3);
        assert_eq!(buffer.as_ref(), b"fix");
        let allocation = buffer.allocation.as_ref().unwrap();
        assert!(allocation.bytes()[3..].iter().all(|&byte| byte == 0));
        buffer.clear();
        buffer.resize(7);
        assert_eq!(buffer.as_ptr(), pointer);
        assert_eq!(buffer.as_ref(), &[0; 7]);
    }

    #[test]
    fn growth_preserves_live_bytes_and_the_drop_erase_covers_the_whole_region() {
        let mut buffer = SecretBuf::from("fixture");
        let size = buffer.allocation.as_ref().unwrap().layout.size();
        let before = buffer.as_ptr();
        buffer.resize(size + 1);
        assert_ne!(buffer.as_ptr(), before);
        assert_eq!(&buffer[..7], b"fixture");
        assert!(buffer[7..].iter().all(|&byte| byte == 0));
        let allocation = buffer.allocation.as_mut().unwrap();
        allocation.bytes_mut().fill(0xff);
        allocation.erase();
        assert!(allocation.bytes().iter().all(|&byte| byte == 0));
    }

    #[test]
    fn a_lock_failure_keeps_the_buffer_available_and_page_isolated() {
        let page = platform::page_size();
        let allocation = Allocation::with_lock(6, |ptr, size| {
            assert_eq!(ptr.as_ptr().addr() % page, 0);
            assert_eq!(size % page, 0);
            false
        });
        assert!(!allocation.locked);
        let mut buffer = SecretBuf {
            allocation: Some(allocation),
            len: 0,
        };
        buffer.extend_from_slice(b"secret");
        assert_eq!(buffer.as_ref(), b"secret");
        assert_eq!(format!("{buffer:?}"), "<6>");
    }

    #[cfg(any(unix, windows))]
    #[test]
    #[ignore = "requires an available operating-system memory-lock quota"]
    fn the_operating_system_locks_an_owned_page() {
        let allocation = Allocation::new(1);
        assert!(allocation.locked);
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "run in an unprivileged process with a zero memory-lock quota"]
    fn denied_operating_system_lock_still_erases() {
        let mut buffer = SecretBuf::from("fixture");
        let allocation = buffer.allocation.as_ref().unwrap();
        assert!(!allocation.locked);
        buffer.clear();
        assert!(
            buffer
                .allocation
                .as_ref()
                .unwrap()
                .bytes()
                .iter()
                .all(|&byte| byte == 0)
        );
    }

    #[test]
    fn bytes_can_hold_the_allocation_without_copying() {
        let owner = SecretBuf::from("owner");
        let pointer = owner.as_ptr();
        let bytes = bytes::Bytes::from_owner(owner);
        assert_eq!(bytes.as_ptr(), pointer);
        let slice = bytes.slice(1..);
        drop(bytes);
        assert_eq!(slice.as_ref(), b"wner");
    }

    #[test]
    fn failed_reads_erase_the_uncounted_tail() {
        struct Fails;
        impl Read for Fails {
            fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
                dst.fill(0xff);
                Err(io::Error::other("fixture error"))
            }
        }

        let mut buffer = SecretBuf::from("keep");
        assert!(buffer.fill_from(Fails, 8).is_err());
        assert_eq!(buffer.as_ref(), b"keep");
        buffer.resize(12);
        assert_eq!(&buffer[4..], &[0; 8]);
        assert_eq!(buffer.fill_from(&b"short"[..], 8).unwrap(), 5);
        assert_eq!(&buffer[12..], b"short");
    }
}
