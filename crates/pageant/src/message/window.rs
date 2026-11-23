use std::{
    ffi::CString,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::{
        Arc,
        atomic::{Ordering, compiler_fence},
    },
};
use windows::{
    Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, ERROR_SUCCESS, ERROR_TIMEOUT, GetLastError, HANDLE, HWND,
            INVALID_HANDLE_VALUE, LPARAM, SetLastError, WAIT_TIMEOUT, WPARAM,
        },
        Security::{
            InitializeSecurityDescriptor, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
            SECURITY_DESCRIPTOR, SetSecurityDescriptorOwner,
        },
        System::{
            DataExchange::COPYDATASTRUCT,
            Memory::{
                CreateFileMappingW, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
                PAGE_READWRITE, UnmapViewOfFile,
            },
            SystemServices::SECURITY_DESCRIPTOR_REVISION,
            Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
                WaitForSingleObject,
            },
        },
        UI::WindowsAndMessaging::{
            FindWindowW, GetWindowThreadProcessId, SMTO_ABORTIFHUNG, SMTO_BLOCK, SMTO_ERRORONEXIT,
            SendMessageTimeoutW, WM_COPYDATA,
        },
    },
    core::{PCWSTR, w},
};
use zeroize::Zeroizing;

use super::{Frame, HEADER, MAX_FRAME, frame_size};
use crate::windows_account::UserSid;

const MESSAGE_ID: usize = 0x804e50ba;
const RESPONSE_TIMEOUT_MS: u32 = 15_000;

#[derive(Clone)]
pub(super) struct Target {
    // HWND is an integer identifier on Windows. Keep the process handle alive to
    // detect termination and retain the process's identity across worker threads.
    window: isize,
    process_id: u32,
    process: Arc<OwnedHandle>,
}

impl Target {
    pub(super) fn find() -> io::Result<Self> {
        // SAFETY: Both strings are static, null-terminated UTF-16 literals.
        let window = unsafe { FindWindowW(w!("Pageant"), w!("Pageant")) }
            .map_err(|_| crate::not_running())?;
        let mut process_id = 0;
        // SAFETY: The OS validates the window handle and receives a live output pointer.
        if unsafe { GetWindowThreadProcessId(window, Some(&mut process_id)) } == 0 {
            return Err(crate::not_running());
        }
        // SAFETY: The PID is nonzero and the successful call returns a new owned handle.
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                process_id,
            )
        }?;
        // SAFETY: OpenProcess succeeded, so this is a valid handle that nothing
        // else owns or closes.
        let process = unsafe { OwnedHandle::from_raw_handle(process.0) };
        let owner = UserSid::from_process(HANDLE(process.as_raw_handle()))?;
        if !UserSid::current()?.equals(owner.as_sid()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Pageant window has a different owner",
            ));
        }
        Ok(Self {
            window: window.0 as isize,
            process_id,
            process: Arc::new(process),
        })
    }

    fn window(&self) -> io::Result<HWND> {
        let handle = HWND(self.window as *mut _);
        let mut process_id = 0;
        // SAFETY: The process handle is retained by self; Windows validates HWND.
        unsafe {
            if WaitForSingleObject(HANDLE(self.process.as_raw_handle()), 0) != WAIT_TIMEOUT
                || GetWindowThreadProcessId(handle, Some(&mut process_id)) == 0
                || process_id != self.process_id
            {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Pageant is no longer running",
                ));
            }
        }
        Ok(handle)
    }

    pub(super) fn query(&self, cookie: &str, message: &[u8]) -> io::Result<Frame> {
        let incomplete = || io::Error::new(io::ErrorKind::InvalidInput, "incomplete agent request");
        let header = message.first_chunk::<HEADER>().ok_or_else(incomplete)?;
        if frame_size(*header)? != message.len() {
            return Err(incomplete());
        }
        let name = mapping_name(cookie)?;
        let mapping = MappedView::new(&name)?;
        let window = self.window()?;
        // SAFETY: The mapped region is at least MAX_FRAME bytes. The request is bounded
        // and the mapping name has not yet been sent to the receiver.
        unsafe {
            ptr::copy_nonoverlapping(message.as_ptr(), mapping.view.Value.cast(), message.len())
        };
        // Clear the view on every path, including a dispatch error or a
        // timeout: the request may carry private key material (add-identity).
        let result = dispatch(window, &name, RESPONSE_TIMEOUT_MS).and_then(|completion| {
            if completion == 0 {
                Err(super::no_answer())
            } else {
                mapping.response()
            }
        });
        mapping.clear();
        result
    }
}

fn mapping_name(cookie: &str) -> io::Result<CString> {
    if cookie.len() > 64
        || !cookie
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    CString::new(format!(
        "PageantRequest{cookie}{}",
        crate::encode_hex(&nonce)
    ))
    .map_err(|_| io::ErrorKind::InvalidInput.into())
}

fn dispatch(window: HWND, name: &CString, timeout_ms: u32) -> io::Result<usize> {
    let data = COPYDATASTRUCT {
        dwData: MESSAGE_ID,
        cbData: name.as_bytes_with_nul().len() as u32,
        lpData: name.as_ptr().cast_mut().cast(),
    };
    let mut completion = 0;
    // SAFETY: WM_COPYDATA marshals `data` and its name into the receiver.
    // This function is synchronous and both input buffers live for the call.
    let status = unsafe {
        SetLastError(ERROR_SUCCESS);
        SendMessageTimeoutW(
            window,
            WM_COPYDATA,
            WPARAM(0),
            LPARAM(ptr::from_ref(&data) as isize),
            SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT,
            timeout_ms,
            Some(&mut completion),
        )
    };
    if status.0 != 0 {
        return Ok(completion);
    }
    // SAFETY: GetLastError reads this thread's Windows error state.
    match unsafe { GetLastError() } {
        ERROR_SUCCESS => Err(super::no_answer()),
        ERROR_TIMEOUT => Err(io::Error::from(io::ErrorKind::TimedOut)),
        error => Err(io::Error::from_raw_os_error(error.0 as i32)),
    }
}

struct MappedView {
    view: MEMORY_MAPPED_VIEW_ADDRESS,
    _handle: OwnedHandle,
}

impl MappedView {
    fn new(name: &CString) -> io::Result<Self> {
        let wide: Vec<_> = name
            .as_bytes_with_nul()
            .iter()
            .map(|b| u16::from(*b))
            .collect();
        let user = UserSid::current()?;
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let descriptor = PSECURITY_DESCRIPTOR(ptr::from_mut(&mut descriptor).cast());
        // SAFETY: The descriptor is writable. The owner SID lives until the OS copies it.
        let mapping = unsafe {
            InitializeSecurityDescriptor(descriptor, SECURITY_DESCRIPTOR_REVISION)?;
            SetSecurityDescriptorOwner(descriptor, Some(user.as_sid()), false)?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: false.into(),
            };
            SetLastError(ERROR_SUCCESS);
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                Some(&attributes),
                PAGE_READWRITE,
                0,
                MAX_FRAME as u32,
                PCWSTR(wide.as_ptr()),
            )?
        };
        // SAFETY: CreateFileMappingW returned a valid handle owned by this function.
        let handle = unsafe { OwnedHandle::from_raw_handle(mapping.0) };
        // SAFETY: Check CreateFileMappingW's same-thread status before accessing the mapping.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        // SAFETY: The live mapping has size MAX_FRAME. The resulting view owns its reference.
        let view = unsafe {
            MapViewOfFile(
                HANDLE(handle.as_raw_handle()),
                FILE_MAP_WRITE,
                0,
                0,
                MAX_FRAME,
            )
        };
        if view.Value.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            view,
            _handle: handle,
        })
    }

    fn response(&self) -> io::Result<Frame> {
        let mut header = [0; HEADER];
        // SAFETY: The call has completed and this live mapping contains MAX_FRAME bytes.
        unsafe { ptr::copy_nonoverlapping(self.view.Value.cast(), header.as_mut_ptr(), HEADER) };
        let size = frame_size(header)?;
        let mut frame = Zeroizing::new(vec![0; size]);
        // SAFETY: Frame size was just checked against the mapped view and the destination size.
        unsafe { ptr::copy_nonoverlapping(self.view.Value.cast(), frame.as_mut_ptr(), size) };
        // The mapping is shared, so its length field can change between the
        // two reads. Keep the one that was checked.
        frame[..HEADER].copy_from_slice(&header);
        Ok(frame)
    }

    fn clear(&self) {
        for offset in 0..MAX_FRAME {
            // SAFETY: This view owns a MAX_FRAME byte writable region, `offset`
            // stays inside it, and no receiver is using it.
            unsafe { ptr::write_volatile(self.view.Value.cast::<u8>().add(offset), 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl Drop for MappedView {
    fn drop(&mut self) {
        // SAFETY: This address came from one successful MapViewOfFile call.
        let _ = unsafe { UnmapViewOfFile(self.view) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, HWND_MESSAGE, WINDOW_EX_STYLE, WINDOW_STYLE,
    };

    #[test]
    fn mapping_cannot_be_reused_until_the_original_view_and_handle_close() {
        let name = mapping_name("fixture").unwrap();
        let view = MappedView::new(&name).unwrap();
        assert!(matches!(
            MappedView::new(&name),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        drop(view);
        assert!(MappedView::new(&name).is_ok());
    }

    #[test]
    fn a_window_that_does_not_handle_the_message_times_out() {
        let (ready, window) = mpsc::channel();
        let (release, finish) = mpsc::channel::<()>();
        let thread = thread::spawn(move || {
            // SAFETY: Use the built-in STATIC class in a private message-only window.
            let handle = unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    w!("STATIC"),
                    w!("ThirtySSH tests"),
                    WINDOW_STYLE(0),
                    0,
                    0,
                    0,
                    0,
                    Some(HWND_MESSAGE),
                    None,
                    None,
                    None,
                )
            }
            .unwrap();
            ready.send(handle.0 as isize).unwrap();
            // Keep the window alive without pumping messages just for the timed dispatch.
            let _ = finish.recv_timeout(Duration::from_secs(3));
            // SAFETY: The window is owned by this thread and has not been destroyed.
            unsafe { DestroyWindow(handle) }.unwrap();
        });
        let window = HWND(window.recv_timeout(Duration::from_secs(2)).unwrap() as *mut _);
        let result = dispatch(window, &mapping_name("timeout-fixture").unwrap(), 40);
        drop(release);
        thread.join().unwrap();
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
    }
}
