use super::{Certificate, CertificateSignaturePolicy, PublicKey};
use crate::{clear_packet::invalid, exec, session::Request};
use ssh_key::certificate::CertType;
use std::{
    io::{self, ErrorKind},
    net::IpAddr,
};

#[derive(Clone)]
pub(crate) struct CertificatePermissions {
    forced_command: Option<Vec<u8>>,
    port_forwarding: bool,
    agent_forwarding: bool,
    x11_forwarding: bool,
    pty: bool,
}

pub(crate) enum CertificateRequest<'a> {
    Allow,
    Reject,
    ForcedExec(&'a [u8]),
}

impl CertificatePermissions {
    pub(crate) fn intersect(self, other: Self) -> io::Result<Self> {
        if let (Some(left), Some(right)) = (&self.forced_command, &other.forced_command)
            && left != right
        {
            return Err(denied(
                "SSH authentication certificates have conflicting forced commands",
            ));
        }
        Ok(Self {
            forced_command: self.forced_command.or(other.forced_command),
            port_forwarding: self.port_forwarding && other.port_forwarding,
            agent_forwarding: self.agent_forwarding && other.agent_forwarding,
            x11_forwarding: self.x11_forwarding && other.x11_forwarding,
            pty: self.pty && other.pty,
        })
    }

    pub(crate) fn for_user(certificate: &Certificate, peer: Option<IpAddr>) -> io::Result<Self> {
        let mut forced_command = None;
        for (name, value) in certificate.critical_options().iter() {
            match name.as_str() {
                "force-command" => {
                    if value.is_empty() || value.contains('\0') {
                        return Err(invalid("invalid SSH certificate force-command"));
                    }
                    forced_command = Some(
                        exec::command_fields(value.as_bytes())
                            .map_err(|_| invalid("oversized SSH certificate force-command"))?,
                    );
                }
                "source-address" => {
                    if !source_matches(value, peer)? {
                        return Err(denied("peer is outside SSH certificate source-address"));
                    }
                }
                _ => return Err(denied("unsupported SSH user certificate critical option")),
            }
        }
        let permit = |name| match certificate.extensions().get(name) {
            Some(data) if data.is_empty() => Ok(true),
            Some(_) => Err(invalid("malformed SSH user certificate extension")),
            None => Ok(false),
        };
        // The runtime does not invoke user startup files.
        permit("permit-user-rc")?;
        Ok(Self {
            forced_command,
            port_forwarding: permit("permit-port-forwarding")?,
            agent_forwarding: permit("permit-agent-forwarding")?,
            x11_forwarding: permit("permit-X11-forwarding")?,
            pty: permit("permit-pty")?,
        })
    }

    pub(crate) fn allows_open(&self, kind: &[u8], fields: &[u8]) -> bool {
        match kind {
            b"session" => fields.is_empty(),
            b"direct-tcpip"
            | b"forwarded-tcpip"
            | b"direct-streamlocal@openssh.com"
            | b"forwarded-streamlocal@openssh.com"
            | b"tun@openssh.com" => self.port_forwarding,
            b"x11" => self.x11_forwarding,
            b"auth-agent@openssh.com" | b"agent-connect" => self.agent_forwarding,
            _ => self.forced_command.is_none(),
        }
    }

    pub(crate) fn allows_global(&self, name: &[u8]) -> bool {
        match name {
            b"tcpip-forward"
            | b"cancel-tcpip-forward"
            | b"streamlocal-forward@openssh.com"
            | b"cancel-streamlocal-forward@openssh.com" => self.port_forwarding,
            _ => self.forced_command.is_none(),
        }
    }

    pub(crate) fn request(&self, name: &[u8], fields: &[u8]) -> io::Result<CertificateRequest<'_>> {
        use CertificateRequest::{Allow, ForcedExec, Reject};
        let allowed = match name {
            b"pty-req" => self.pty,
            b"auth-agent-req@openssh.com" | b"agent-req" => self.agent_forwarding,
            b"x11-req" => self.x11_forwarding,
            _ => true,
        };
        if !allowed {
            return Ok(Reject);
        }
        let Some(command) = &self.forced_command else {
            return Ok(Allow);
        };
        match name {
            b"exec" | b"shell" | b"subsystem" => {
                Request::decode(name, fields)?;
                Ok(ForcedExec(command))
            }
            b"pty-req"
            | b"auth-agent-req@openssh.com"
            | b"agent-req"
            | b"x11-req"
            | b"window-change"
            | b"signal"
            | b"xon-xoff"
            | b"exit-status"
            | b"exit-signal" => Ok(Allow),
            // A generic application may execute arbitrary code through an
            // extension or let an environment variable alter the command.
            _ => Ok(Reject),
        }
    }
}

/// Check an explicitly trusted issuer, exact user principal, validity and
/// supported critical options. Supply the trusted peer IP for source-address
/// restrictions. Server authentication also enforces these restrictions.
pub fn validate_user_certificate_at(
    certificate: &Certificate,
    authority: &PublicKey,
    principal: &str,
    unix_time: u64,
    peer: Option<IpAddr>,
) -> io::Result<bool> {
    CertificateSignaturePolicy::default().validate_user_certificate_at(
        certificate,
        authority,
        principal,
        unix_time,
        peer,
    )
}

impl CertificateSignaturePolicy {
    /// Validate user certificate trust with this issuer signature policy.
    /// Critical options are checked against the trusted peer address.
    pub fn validate_user_certificate_at(
        self,
        certificate: &Certificate,
        authority: &PublicKey,
        principal: &str,
        unix_time: u64,
        peer: Option<IpAddr>,
    ) -> io::Result<bool> {
        if !self.validate_trust_at(certificate, authority, principal, CertType::User, unix_time)? {
            return Ok(false);
        }
        match CertificatePermissions::for_user(certificate, peer) {
            Ok(_) => Ok(true),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::PermissionDenied | ErrorKind::InvalidData
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}

fn source_matches(list: &str, peer: Option<IpAddr>) -> io::Result<bool> {
    let malformed = || invalid("invalid SSH certificate source-address");
    let mut matched = false;
    for item in list.split(',') {
        let (network, prefix) = match item.split_once('/') {
            Some((ip, prefix))
                if !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()) =>
            {
                (ip, Some(prefix.parse::<u8>().map_err(|_| malformed())?))
            }
            Some(_) => return Err(malformed()),
            None => (item, None),
        };
        let ip: IpAddr = network.parse().map_err(|_| malformed())?;
        let (network, width, candidate) = match ip {
            IpAddr::V4(v4) => (
                u128::from(u32::from(v4)),
                32,
                peer.map(|ip| ip.to_canonical()).and_then(|ip| {
                    if let IpAddr::V4(v4) = ip {
                        Some(u128::from(u32::from(v4)))
                    } else {
                        None
                    }
                }),
            ),
            IpAddr::V6(v6) => (
                u128::from(v6),
                128,
                // An IPv4 peer seen through a dual-stack socket is still an
                // IPv4 peer, and matches IPv4 entries only.
                peer.map(|ip| ip.to_canonical()).and_then(|ip| {
                    if let IpAddr::V6(v6) = ip {
                        Some(u128::from(v6))
                    } else {
                        None
                    }
                }),
            ),
        };
        let prefix = prefix.unwrap_or(width);
        if prefix > width {
            return Err(malformed());
        }
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (width - prefix)
        };
        if network & !mask != 0 {
            return Err(malformed());
        }
        matched |= candidate.is_some_and(|address| address & mask == network);
    }
    Ok(matched)
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PrivateKey;
    use ssh_key::{certificate::Builder, private::Ed25519Keypair};

    #[test]
    fn source_addresses_accept_exact_hosts_and_cidrs_only_in_their_family() {
        let matches = |list, peer: &str| source_matches(list, Some(peer.parse().unwrap())).unwrap();
        assert!(matches("127.0.0.1", "127.0.0.1"));
        assert!(matches("127.0.0.0/8", "::ffff:127.0.0.8"));
        assert!(matches("192.0.2.0/31", "192.0.2.1"));
        assert!(!matches("192.0.2.0/31", "192.0.2.2"));
        assert!(!matches("0.0.0.0/0", "::1"));
        assert!(!matches("::/0", "127.0.0.1"));
        for list in [
            "",
            "127.0.0.0/33",
            "::/129",
            "::/0,",
            "127.0.0.0/+8",
            "fe80::1%zone",
        ] {
            assert!(source_matches(list, None).is_err(), "{list}");
        }
    }

    #[test]
    fn certificate_extensions_grant_only_the_associated_actions() {
        let authority = PrivateKey::new(Ed25519Keypair::from_seed(&[2; 32]).into(), "").unwrap();
        let identity = PrivateKey::new(Ed25519Keypair::from_seed(&[3; 32]).into(), "").unwrap();
        let issue = |data| {
            let mut builder =
                Builder::new(vec![1; 32], identity.public_key().key_data().clone(), 1, 2).unwrap();
            builder
                .cert_type(CertType::User)
                .unwrap()
                .valid_principal("fixture")
                .unwrap()
                .extension("permit-port-forwarding", data)
                .unwrap()
                .extension("something@example.test", "ignored")
                .unwrap();
            builder.sign(&authority).unwrap()
        };
        let permissions = CertificatePermissions::for_user(&issue(""), None).unwrap();
        assert!(permissions.allows_open(b"direct-tcpip", &[]));
        assert!(permissions.allows_global(b"tcpip-forward"));
        assert!(!permissions.allows_open(b"x11", &[]));
        assert!(!permissions.allows_open(b"auth-agent@openssh.com", &[]));
        assert!(!permissions.allows_open(b"agent-connect", &[]));
        assert!(matches!(
            permissions.request(b"pty-req", &[]).unwrap(),
            CertificateRequest::Reject
        ));
        assert!(matches!(
            permissions.request(b"x11-req", &[]).unwrap(),
            CertificateRequest::Reject
        ));
        assert!(matches!(
            permissions
                .request(b"auth-agent-req@openssh.com", &[])
                .unwrap(),
            CertificateRequest::Reject
        ));
        assert!(matches!(
            permissions.request(b"agent-req", &[]).unwrap(),
            CertificateRequest::Reject
        ));
        assert!(CertificatePermissions::for_user(&issue("unexpected"), None).is_err());
    }

    #[test]
    fn combining_certificate_factors_keeps_the_stricter_permissions() {
        let permissions = |force: &str, pty, port_forwarding| CertificatePermissions {
            forced_command: Some(exec::command_fields(force.as_bytes()).unwrap()),
            port_forwarding,
            agent_forwarding: false,
            x11_forwarding: false,
            pty,
        };
        let combined = permissions("fixture", true, false)
            .intersect(permissions("fixture", false, true))
            .unwrap();
        assert!(!combined.allows_global(b"tcpip-forward"));
        assert!(matches!(
            combined.request(b"pty-req", &[]).unwrap(),
            CertificateRequest::Reject
        ));
        assert!(matches!(
            combined.request(b"shell", &[]).unwrap(),
            CertificateRequest::ForcedExec(_)
        ));
        let conflict = permissions("fixture-a", false, false).intersect(permissions(
            "fixture-b",
            false,
            false,
        ));
        assert!(matches!(conflict, Err(error) if error.kind() == ErrorKind::PermissionDenied));
    }
}
