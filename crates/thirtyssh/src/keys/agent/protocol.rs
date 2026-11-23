use super::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) const FAILURE: u8 = 5;
pub(super) const SUCCESS: u8 = 6;
pub(super) const REQUEST_IDENTITIES: u8 = 11;
pub(super) const IDENTITIES_ANSWER: u8 = 12;
pub(super) const SIGN_REQUEST: u8 = 13;
pub(super) const SIGN_RESPONSE: u8 = 14;
pub(super) const ADD_IDENTITY: u8 = 17;
pub(super) const REMOVE_IDENTITY: u8 = 18;
pub(super) const REMOVE_ALL: u8 = 19;
pub(super) const ADD_SMARTCARD: u8 = 20;
pub(super) const REMOVE_SMARTCARD: u8 = 21;
pub(super) const LOCK: u8 = 22;
pub(super) const UNLOCK: u8 = 23;
pub(super) const ADD_CONSTRAINED: u8 = 25;
pub(super) const ADD_SMARTCARD_CONSTRAINED: u8 = 26;
pub(super) const EXTENSION: u8 = 27;
pub(super) const EXTENSION_FAILURE: u8 = 28;
pub(super) const EXTENSION_RESPONSE: u8 = 29;
pub(super) const CONSTRAIN_LIFETIME: u8 = 1;
pub(super) const CONSTRAIN_CONFIRM: u8 = 2;
pub(super) const CONSTRAIN_EXTENSION: u8 = 255;
pub(super) const RSA_SHA256: u32 = 2;
pub(super) const RSA_SHA512: u32 = 4;
pub(super) const MAX_FRAME: usize = 256 * 1024;

pub(super) fn check_frame_size(size: usize) -> Result<(), Error> {
    if (1..=MAX_FRAME).contains(&size) {
        Ok(())
    } else {
        Err(Error::Protocol)
    }
}

pub(super) fn protocol(_: impl std::error::Error) -> Error {
    Error::Protocol
}

pub(super) async fn read_frame_size(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<Option<usize>, Error> {
    let mut length = [0u8; 4];
    if reader.read(&mut length[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut length[1..]).await?;
    let size = u32::from_be_bytes(length) as usize;
    check_frame_size(size)?;
    Ok(Some(size))
}

pub(super) async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    body: &[u8],
) -> Result<(), Error> {
    check_frame_size(body.len())?;
    writer.write_u32(body.len() as u32).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}
