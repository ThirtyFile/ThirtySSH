use super::{
    Attempt, BannerObserver, Client, FAILURE, SUCCESS, malformed, request, signature_input,
};
use crate::{clear_packet::invalid, kex, wire::Reader};
use pkcs8::{ObjectIdentifier, der::Decode};
use std::{
    future::{Future, ready},
    io, str,
};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

const NAME: &[u8] = b"gssapi-with-mic";
const RESPONSE: u8 = 60;
const TOKEN: u8 = 61;
const EXCHANGE_COMPLETE: u8 = 63;
const ERROR: u8 = 64;
const ERROR_TOKEN: u8 = 65;
const MIC: u8 = 66;
const MAX_MECHANISMS: usize = 64;
const MAX_PAYLOAD: usize = 32_768;
const MAX_MESSAGES: usize = 64;
const SPNEGO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.2");

/// What the server sent for the security context to consume.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GssInput<'a> {
    /// The server chose this mechanism, a DER object identifier from the
    /// offered list. The context produces its first token.
    Mechanism(&'a [u8]),
    /// The server's next token for the chosen mechanism.
    Token(&'a [u8]),
}

/// How far a step brought the security context.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GssProgress {
    /// Send this token and wait for the server's next one.
    Continue(Vec<u8>),
    /// The context is established. A last token, if the mechanism produced
    /// one, is sent before the exchange is completed.
    Established(Option<Vec<u8>>),
}

/// Why the server ended a GSSAPI exchange.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GssRejection {
    /// The server's GSSAPI status codes and its message for the user.
    Status {
        major: u32,
        minor: u32,
        message: String,
    },
    /// An error token for the mechanism to interpret.
    Token(Vec<u8>),
}

/// A client-side GSSAPI security context, supplied by the application for
/// the host it has already verified.
pub trait GssContext {
    /// Advance the context with what the server sent.
    fn step(&mut self, input: GssInput<'_>)
    -> impl Future<Output = io::Result<GssProgress>> + Send;

    /// Called once, after the context is established, for the message
    /// integrity code over `data` that binds the context to this SSH
    /// session. Return `None` only when the context cannot protect
    /// integrity.
    fn mic(&mut self, data: &[u8]) -> impl Future<Output = io::Result<Option<Vec<u8>>>> + Send;

    /// The server reported why the exchange failed. Authentication has
    /// already failed when this is called.
    fn rejected(&mut self, _rejection: GssRejection) -> impl Future<Output = ()> + Send {
        ready(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Exchange {
    Select,
    Tokens,
    Complete,
    Failed,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    /// Authenticate through a GSSAPI security context the application owns.
    pub async fn gssapi(
        &mut self,
        username: &str,
        mechanisms: &[Vec<u8>],
        context: &mut impl GssContext,
    ) -> io::Result<Attempt> {
        self.gssapi_observed(username, mechanisms, context, &mut ())
            .await
    }

    pub(crate) async fn gssapi_observed(
        &mut self,
        username: &str,
        mechanisms: &[Vec<u8>],
        context: &mut impl GssContext,
        observer: &mut impl BannerObserver,
    ) -> io::Result<Attempt> {
        let mut packet = request(username, NAME)?;
        let mic_data = signature_input(self.transport.session_id(), &packet)?;
        append_mechanisms(&mut packet, mechanisms)?;
        self.begin_attempt(observer).await?;
        self.transport.send(&packet).await?;

        let mut state = Exchange::Select;
        for _ in 0..MAX_MESSAGES {
            let packet = Zeroizing::new(self.read_reply(observer).await?);
            check_size(packet.len())?;
            let step = match packet[0] {
                FAILURE => return self.finish_attempt(username, &packet),
                SUCCESS if state == Exchange::Complete => {
                    return self.finish_attempt(username, &packet);
                }
                RESPONSE if state == Exchange::Select => {
                    let [selected] = kex::decode::<1>(&packet, Some(RESPONSE))?;
                    if !mechanisms
                        .iter()
                        .any(|offered| offered.as_slice() == selected)
                    {
                        return Err(invalid("server selected an unoffered SSH GSSAPI mechanism"));
                    }
                    context.step(GssInput::Mechanism(selected)).await?
                }
                TOKEN if state == Exchange::Tokens => {
                    let [token] = kex::decode::<1>(&packet, Some(TOKEN))?;
                    context.step(GssInput::Token(token)).await?
                }
                ERROR => {
                    context.rejected(read_status(&packet[1..])?).await;
                    state = Exchange::Failed;
                    continue;
                }
                ERROR_TOKEN => {
                    let [token] = kex::decode::<1>(&packet, Some(ERROR_TOKEN))?;
                    context.rejected(GssRejection::Token(token.to_vec())).await;
                    state = Exchange::Failed;
                    continue;
                }
                _ => return Err(invalid("unexpected SSH GSSAPI authentication response")),
            };
            state = self.send_progress(step, context, &mic_data).await?;
        }
        Err(invalid("too many SSH GSSAPI authentication messages"))
    }

    async fn send_progress(
        &mut self,
        progress: GssProgress,
        context: &mut impl GssContext,
        mic_data: &[u8],
    ) -> io::Result<Exchange> {
        let (token, established) = match progress {
            GssProgress::Continue(token) => (Some(token), false),
            GssProgress::Established(token) => (token, true),
        };
        if let Some(token) = token.map(Zeroizing::new).filter(|token| !token.is_empty()) {
            check_size(5 + token.len())?;
            let packet = Zeroizing::new(kex::fields(Some(TOKEN), &[&token])?);
            self.transport.send(&packet).await?;
        }
        if !established {
            return Ok(Exchange::Tokens);
        }
        let packet = match context.mic(mic_data).await?.map(Zeroizing::new) {
            Some(mic) => {
                check_size(5 + mic.len())?;
                if mic.is_empty() {
                    return Err(invalid("empty SSH GSSAPI MIC"));
                }
                kex::fields(Some(MIC), &[&mic])?
            }
            None => vec![EXCHANGE_COMPLETE],
        };
        self.transport.send(&Zeroizing::new(packet)).await?;
        Ok(Exchange::Complete)
    }
}

fn check_size(size: usize) -> io::Result<()> {
    if size > MAX_PAYLOAD {
        return Err(invalid("SSH GSSAPI packet exceeds limit"));
    }
    Ok(())
}

fn append_mechanisms(packet: &mut Vec<u8>, mechanisms: &[Vec<u8>]) -> io::Result<()> {
    if mechanisms.is_empty() || mechanisms.len() > MAX_MECHANISMS {
        return Err(invalid("invalid SSH GSSAPI mechanism count"));
    }
    let size = mechanisms.iter().fold(packet.len() + 4, |size, oid| {
        size.saturating_add(4 + oid.len())
    });
    check_size(size)?;
    for mechanism in mechanisms {
        let oid = ObjectIdentifier::from_der(mechanism)
            .map_err(|_| invalid("invalid SSH GSSAPI mechanism OID"))?;
        if oid == SPNEGO {
            return Err(invalid("SSH GSSAPI does not allow SPNEGO"));
        }
    }
    packet.reserve(size - packet.len());
    packet.extend_from_slice(&(mechanisms.len() as u32).to_be_bytes());
    for mechanism in mechanisms {
        packet.extend_from_slice(&(mechanism.len() as u32).to_be_bytes());
        packet.extend_from_slice(mechanism);
    }
    Ok(())
}

fn read_status(packet: &[u8]) -> io::Result<GssRejection> {
    let mut reader = Reader::new(packet);
    let major = reader.uint32().map_err(malformed)?;
    let minor = reader.uint32().map_err(malformed)?;
    let message = str::from_utf8(reader.string().map_err(malformed)?)
        .map_err(|_| invalid("invalid UTF-8 in SSH GSSAPI error"))?
        .to_owned();
    reader.string().map_err(malformed)?;
    reader.finish().map_err(malformed)?;
    Ok(GssRejection::Status {
        major,
        minor,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mechanism_offers_require_bounded_der_oids_and_exclude_spnego() {
        let mut packet = request("fixture", NAME).unwrap();
        let oid = vec![0x06, 2, 0x2a, 3];
        assert!(append_mechanisms(&mut packet, &[]).is_err());
        assert!(append_mechanisms(&mut packet, &vec![oid.clone(); MAX_MECHANISMS + 1]).is_err());
        assert!(append_mechanisms(&mut packet, &[vec![0x06, 2, 0x2a]]).is_err());
        assert!(append_mechanisms(&mut packet, &[vec![0x06, 6, 0x2b, 6, 1, 5, 5, 2]]).is_err());
        assert!(append_mechanisms(&mut packet, &[vec![0; MAX_PAYLOAD]]).is_err());
        assert_eq!(packet, request("fixture", NAME).unwrap());
        append_mechanisms(&mut packet, std::slice::from_ref(&oid)).unwrap();
        assert!(packet.ends_with(&oid));
    }
}
