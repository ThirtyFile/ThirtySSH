#[cfg(feature = "named-pipe")]
use std::{ffi::OsString, os::windows::ffi::OsStringExt};
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use windows::Win32::{
    Foundation::HANDLE,
    Security::{EqualSid, GetTokenInformation, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
#[cfg(feature = "named-pipe")]
use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Globalization::{CP_ACP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS, MultiByteToWideChar},
        Security::{
            Authentication::Identity::{GetUserNameExA, NameUserPrincipal},
            Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT},
            IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            WinBuiltinAdministratorsSid, WinLocalSystemSid,
        },
        System::WindowsProgramming::GetUserNameA,
    },
    core::PSTR,
};

#[cfg(feature = "named-pipe")]
pub(super) fn name() -> io::Result<OsString> {
    // Pageant constructs the pipe name with the Windows ANSI APIs.
    let mut size = 0;
    // SAFETY: These discovery calls receive only a writable length pointer.
    unsafe { GetUserNameExA(NameUserPrincipal, None, &mut size) };
    if size != 0 {
        let mut name = vec![0u8; size as usize];
        // SAFETY: `name` has the advertised capacity and lives for the call.
        if unsafe { GetUserNameExA(NameUserPrincipal, Some(PSTR(name.as_mut_ptr())), &mut size) } {
            return component(&name, true);
        }
    }

    size = 0;
    // SAFETY: Query the required length, then give Windows a buffer of that length.
    let _ = unsafe { GetUserNameA(None, &mut size) };
    let mut name = vec![0u8; size.max(256) as usize];
    size = name.len() as u32;
    // SAFETY: `name` is writable for `size` bytes, the length passed with it.
    unsafe { GetUserNameA(Some(PSTR(name.as_mut_ptr())), &mut size) }?;
    component(&name, false)
}

#[cfg(feature = "named-pipe")]
fn unusable_name() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the Windows account name cannot name a Pageant pipe",
    )
}

#[cfg(feature = "named-pipe")]
fn component(name: &[u8], principal: bool) -> io::Result<OsString> {
    let end = name
        .iter()
        .position(|&unit| unit == 0 || (principal && unit == b'@'))
        .unwrap_or(name.len());
    let name = &name[..end];
    if name.is_empty() {
        return Err(unusable_name());
    }
    let flags = MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0);
    // SAFETY: Windows reads only the supplied input bytes and sizes or fills the output slice.
    let length = unsafe { MultiByteToWideChar(CP_ACP, flags, name, None) };
    if length <= 0 {
        return Err(unusable_name());
    }
    let mut wide = vec![0u16; length as usize];
    // SAFETY: Both buffers are slices, so Windows receives their real lengths.
    if unsafe { MultiByteToWideChar(CP_ACP, flags, name, Some(&mut wide)) } != length
        || wide.contains(&u16::from(b'\\'))
        || wide.contains(&u16::from(b'/'))
    {
        return Err(unusable_name());
    }
    Ok(OsString::from_wide(&wide))
}

pub(super) struct UserSid(Vec<usize>);

impl UserSid {
    pub(super) fn current() -> io::Result<Self> {
        // SAFETY: GetCurrentProcess returns the current process pseudo-handle.
        Self::from_process(unsafe { GetCurrentProcess() })
    }

    pub(super) fn from_process(process: HANDLE) -> io::Result<Self> {
        let mut token = HANDLE::default();
        // SAFETY: `process` refers to the current process or an open process handle.
        // On success the new token handle is owned.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }?;
        // SAFETY: OpenProcessToken succeeded, so this is a valid handle that
        // nothing else owns or closes.
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
        let token_handle = HANDLE(token.as_raw_handle());
        let mut size = 0;
        // SAFETY: The first call queries the length, and the second writes into aligned storage.
        let _ = unsafe { GetTokenInformation(token_handle, TokenUser, None, 0, &mut size) };
        if (size as usize) < size_of::<TOKEN_USER>() {
            return Err(io::Error::other("Windows did not provide a token user"));
        }
        let mut user = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        // SAFETY: `user` holds at least `size` bytes, aligned for TOKEN_USER.
        unsafe {
            GetTokenInformation(
                token_handle,
                TokenUser,
                Some(user.as_mut_ptr().cast()),
                size,
                &mut size,
            )
        }?;
        Ok(Self(user))
    }

    pub(super) fn as_sid(&self) -> PSID {
        // SAFETY: Windows populated TOKEN_USER, including an in-buffer SID, on success.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    pub(super) fn equals(&self, other: PSID) -> bool {
        // SAFETY: `other` is either null or a SID returned by a live Windows object.
        !other.0.is_null() && unsafe { EqualSid(self.as_sid(), other) }.is_ok()
    }
}

/// Who may own a pipe that agent traffic is sent to.
#[cfg(feature = "named-pipe")]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum PipeOwner {
    /// Only the current account, as Pageant runs.
    CurrentUser,
    /// The current account, or the system itself: an agent that runs as a
    /// Windows service owns its pipe as SYSTEM or as the Administrators
    /// group. No unprivileged account can create a pipe with either owner.
    CurrentUserOrSystem,
}

/// Validate the owner of the opened pipe before sending any agent payload.
#[cfg(feature = "named-pipe")]
pub(super) fn check_pipe_owner(pipe: HANDLE, allowed: PipeOwner) -> io::Result<()> {
    let user = UserSid::current()?;
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: The pipe handle lives for the query. Windows allocates the descriptor and
    // returns an owner pointer into it, both of which are kept alive through EqualSid.
    unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
        .ok()?
    };
    let system = || {
        [WinLocalSystemSid, WinBuiltinAdministratorsSid]
            .into_iter()
            // SAFETY: `owner` is a SID inside the descriptor, which is still allocated.
            .any(|kind| !owner.0.is_null() && unsafe { IsWellKnownSid(owner, kind) }.as_bool())
    };
    let matches = user.equals(owner) || (allowed == PipeOwner::CurrentUserOrSystem && system());
    // SAFETY: GetSecurityInfo transfers ownership of the descriptor allocated with LocalAlloc.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    if !matches {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Pageant pipe has a different owner",
        ));
    }
    Ok(())
}
