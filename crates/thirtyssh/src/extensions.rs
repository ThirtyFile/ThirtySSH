//! RFC 8308 message order and the server signature algorithm announcement.
use crate::{
    clear_packet::invalid,
    identification::Role,
    keys::Algorithm,
    wire::{Reader, Writer},
};
use std::{
    io::{self, ErrorKind},
    sync::Arc,
};
use tokio::sync::watch;

pub(crate) const EXT_INFO: u8 = 7;
const USERAUTH_SUCCESS: u8 = 52;
const SERVER_SIG_ALGS: &[u8] = b"server-sig-algs";
const AGENT_FORWARD: &[u8] = b"agent-forward";

#[derive(Default)]
struct Announcements {
    signature_algorithms: Option<Arc<str>>,
    standard_agent_forwarding: Option<bool>,
}

#[derive(Clone)]
enum SignatureAlgorithms {
    Pending,
    Known(Option<Arc<str>>),
}

/// Observe the peer's public-key user authentication algorithms while a
/// client connection is being driven.
#[derive(Clone)]
pub struct ServerSignatureAlgorithms(watch::Receiver<SignatureAlgorithms>);

impl ServerSignatureAlgorithms {
    /// Return the current announcement, if one has been received.
    pub fn current(&self) -> Option<Arc<str>> {
        match &*self.0.borrow() {
            SignatureAlgorithms::Pending => None,
            SignatureAlgorithms::Known(algorithms) => algorithms.clone(),
        }
    }

    /// Wait for an announcement or for user authentication to succeed.
    /// A peer may leave the announcement absent. Callers can set a deadline
    /// while authentication is still pending.
    pub async fn wait(&mut self) -> io::Result<Option<Arc<str>>> {
        let state = self
            .0
            .wait_for(|state| matches!(state, SignatureAlgorithms::Known(_)))
            .await
            .map_err(|_| io::Error::new(ErrorKind::BrokenPipe, "SSH connection closed"))?;
        match &*state {
            SignatureAlgorithms::Known(algorithms) => Ok(algorithms.clone()),
            SignatureAlgorithms::Pending => {
                unreachable!("wait predicate only accepts known values")
            }
        }
    }
}

enum Phase {
    FirstPacket,
    BeforeAuthSuccess,
    ExpectAuthSuccess,
    Closed,
}

pub(crate) struct Extensions {
    role: Role,
    phase: Phase,
    announcements: Announcements,
    signature_algorithms_observer: Option<watch::Sender<SignatureAlgorithms>>,
}

impl Extensions {
    pub(crate) fn new(role: Role) -> Self {
        Self {
            role,
            phase: Phase::FirstPacket,
            announcements: Announcements::default(),
            signature_algorithms_observer: None,
        }
    }

    pub(crate) fn server_signature_algorithms(&self) -> Option<&str> {
        self.announcements.signature_algorithms.as_deref()
    }

    pub(crate) fn watch_server_signature_algorithms(&mut self) -> ServerSignatureAlgorithms {
        let state = self.signature_algorithms_state();
        let sender = self
            .signature_algorithms_observer
            .get_or_insert_with(|| watch::Sender::new(state));
        ServerSignatureAlgorithms(sender.subscribe())
    }

    fn signature_algorithms_state(&self) -> SignatureAlgorithms {
        let algorithms = &self.announcements.signature_algorithms;
        if algorithms.is_some() || matches!(self.phase, Phase::Closed) {
            SignatureAlgorithms::Known(algorithms.clone())
        } else {
            SignatureAlgorithms::Pending
        }
    }

    fn publish_signature_algorithms(&self) {
        if let Some(sender) = &self.signature_algorithms_observer {
            sender.send_replace(self.signature_algorithms_state());
        }
    }

    pub(crate) fn supports_standard_agent_forwarding(&self) -> bool {
        self.announcements.standard_agent_forwarding == Some(true)
    }

    /// Observe each protected packet once, before queuing or delivering it.
    /// Returns true when the packet belongs to the extension layer.
    pub(crate) fn observe(&mut self, packet: &[u8]) -> io::Result<bool> {
        if packet[0] != EXT_INFO {
            if matches!(self.phase, Phase::ExpectAuthSuccess) && packet != [USERAUTH_SUCCESS] {
                return Err(invalid(
                    "SSH_MSG_EXT_INFO must precede user authentication success",
                ));
            }
            if packet == [USERAUTH_SUCCESS] {
                self.phase = Phase::Closed;
                self.publish_signature_algorithms();
            } else if matches!(self.phase, Phase::FirstPacket) {
                self.phase = if self.role == Role::Client {
                    Phase::BeforeAuthSuccess
                } else {
                    Phase::Closed
                };
            }
            return Ok(false);
        }
        let next = match self.phase {
            Phase::FirstPacket if self.role == Role::Client => Phase::BeforeAuthSuccess,
            Phase::FirstPacket => Phase::Closed,
            Phase::BeforeAuthSuccess => Phase::ExpectAuthSuccess,
            _ => return Err(invalid("unexpected SSH_MSG_EXT_INFO")),
        };
        self.announcements = decode(&packet[1..], self.role)?;
        self.phase = next;
        self.publish_signature_algorithms();
        Ok(true)
    }
}

pub(crate) fn server_announcement(
    agent_forwarding: bool,
    signature_algorithms: &[Algorithm],
) -> io::Result<Vec<u8>> {
    let names = signature_algorithms
        .iter()
        .map(|algorithm| algorithm.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let forwarding_size = if agent_forwarding {
        9 + AGENT_FORWARD.len()
    } else {
        0
    };
    let mut output = vec![0; 1 + 4 + 4 + SERVER_SIG_ALGS.len() + 4 + names.len() + forwarding_size];
    let mut writer = Writer::new(&mut output);
    writer.byte(EXT_INFO).map_err(io::Error::other)?;
    writer
        .uint32(1 + u32::from(agent_forwarding))
        .map_err(io::Error::other)?;
    writer.string(SERVER_SIG_ALGS).map_err(io::Error::other)?;
    writer.name_list(&names).map_err(io::Error::other)?;
    if agent_forwarding {
        writer.string(AGENT_FORWARD).map_err(io::Error::other)?;
        writer.string(b"0").map_err(io::Error::other)?;
    }
    Ok(output)
}

fn decode(payload: &[u8], role: Role) -> io::Result<Announcements> {
    let mut reader = Reader::new(payload);
    let wire_error = |error| io::Error::new(ErrorKind::InvalidData, error);
    let count = reader.uint32().map_err(wire_error)? as usize;
    if count > reader.remaining().len() / 8 {
        return Err(invalid("truncated SSH extension announcement"));
    }
    let mut announcements = Announcements::default();
    for _ in 0..count {
        let name = reader.string().map_err(wire_error)?;
        if name.is_empty() || !name.iter().all(u8::is_ascii_graphic) {
            return Err(invalid("invalid SSH extension name"));
        }
        if role == Role::Client && name == SERVER_SIG_ALGS {
            if announcements.signature_algorithms.is_some() {
                return Err(invalid("duplicate SSH server-sig-algs extension"));
            }
            let names = reader.name_list().map_err(wire_error)?;
            if names
                .split(',')
                .any(|name| name.len() > 64 || !name.as_bytes().iter().all(u8::is_ascii_graphic))
            {
                return Err(invalid("invalid SSH server signature algorithm"));
            }
            announcements.signature_algorithms = Some(Arc::from(names));
        } else if role == Role::Client && name == AGENT_FORWARD {
            if announcements.standard_agent_forwarding.is_some() {
                return Err(invalid("duplicate SSH agent-forward extension"));
            }
            let version = reader.string().map_err(wire_error)?;
            announcements.standard_agent_forwarding = Some(version == b"0");
        } else {
            reader.string().map_err(wire_error)?;
        }
    }
    reader.finish().map_err(wire_error)?;
    Ok(announcements)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SIGNATURE_ALGORITHMS;

    fn extensions(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut packet = [0; 256];
        let mut writer = Writer::new(&mut packet);
        writer.byte(EXT_INFO).unwrap();
        writer.uint32(entries.len() as u32).unwrap();
        for (name, value) in entries {
            writer.string(name).unwrap();
            writer.string(value).unwrap();
        }
        writer.written().to_vec()
    }

    #[test]
    fn first_announcement_and_pre_success_replacement() {
        let mut peer = Extensions::new(Role::Client);
        assert!(
            peer.observe(&server_announcement(true, &SIGNATURE_ALGORITHMS).unwrap())
                .unwrap()
        );
        assert!(peer.supports_standard_agent_forwarding());
        assert_eq!(
            peer.server_signature_algorithms(),
            Some(if cfg!(feature = "rsa") {
                "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256"
            } else {
                "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521"
            })
        );
        assert!(!peer.observe(&[6]).unwrap());
        assert!(
            peer.observe(&extensions(&[
                (b"unknown", b"\0\xffopaque"),
                (SERVER_SIG_ALGS, b"rsa-sha2-256")
            ]))
            .unwrap()
        );
        assert!(!peer.observe(&[USERAUTH_SUCCESS]).unwrap());
        assert_eq!(peer.server_signature_algorithms(), Some("rsa-sha2-256"));
        assert!(!peer.supports_standard_agent_forwarding());
        assert!(
            peer.observe(&server_announcement(false, &SIGNATURE_ALGORITHMS).unwrap())
                .is_err()
        );
    }

    #[tokio::test]
    async fn signature_observers_track_replacement_and_authentication_completion() {
        let mut peer = Extensions::new(Role::Client);
        let mut watch = peer.watch_server_signature_algorithms();
        assert!(watch.current().is_none());
        peer.observe(&extensions(&[(SERVER_SIG_ALGS, b"ssh-rsa")]))
            .unwrap();
        assert_eq!(watch.wait().await.unwrap().as_deref(), Some("ssh-rsa"));
        peer.observe(&extensions(&[(b"unrelated", b"value")]))
            .unwrap();
        peer.observe(&[USERAUTH_SUCCESS]).unwrap();
        assert!(watch.wait().await.unwrap().is_none());
        assert!(
            peer.watch_server_signature_algorithms()
                .wait()
                .await
                .unwrap()
                .is_none()
        );

        let mut peer = Extensions::new(Role::Client);
        let mut watch = peer.watch_server_signature_algorithms();
        drop(peer);
        assert_eq!(
            watch.wait().await.unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn rejects_duplicate_algorithms_malformed_counts_and_wrong_order() {
        let mut client = Extensions::new(Role::Client);
        assert!(client.observe(&[EXT_INFO, 255, 255, 255, 255]).is_err());
        assert!(
            client
                .observe(&extensions(&[
                    (SERVER_SIG_ALGS, b""),
                    (SERVER_SIG_ALGS, b"ssh-ed25519")
                ]))
                .is_err()
        );
        client.observe(&[6]).unwrap();
        client
            .observe(&server_announcement(false, &SIGNATURE_ALGORITHMS).unwrap())
            .unwrap();
        assert!(client.observe(&[51]).is_err());

        let mut server = Extensions::new(Role::Server);
        let info = extensions(&[(b"unknown", b"\x00\xc0")]);
        assert!(server.observe(&info).unwrap());
        assert!(server.observe(&info).is_err());
    }

    #[test]
    fn agent_forwarding_accepts_only_version_zero() {
        let mut peer = Extensions::new(Role::Client);
        assert!(peer.observe(&extensions(&[(AGENT_FORWARD, b"1")])).unwrap());
        assert!(!peer.supports_standard_agent_forwarding());
        let mut duplicate = Extensions::new(Role::Client);
        assert!(
            duplicate
                .observe(&extensions(&[(AGENT_FORWARD, b"0"), (AGENT_FORWARD, b"1")]))
                .is_err()
        );
    }
}
