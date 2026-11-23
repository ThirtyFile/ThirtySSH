//! Initial SSH identification and KEXINIT exchange.
//! The returned transcript can be used to compute the exchange hash.
use crate::{
    algorithms::{
        Cipher, Compression, CompressionAlgorithms, DirectionPreferences, Kex, Mac,
        PacketAlgorithms, Suite, TransportPreferences,
    },
    clear_packet::{self, invalid},
    identification::{self, Role},
    keys::Algorithm,
    protocol_error::{ProtocolError, unexpected_initial_message},
    wire::{Reader, Writer},
};
use std::io::{self, ErrorKind};
use tokio::io::{AsyncBufRead, AsyncWrite};

pub(crate) const KEXINIT: u8 = 20;
pub(crate) const NEWKEYS: &[u8] = &[21];

/// The exact identification and KEXINIT payload sent by one peer.
pub struct PeerTranscript {
    pub identification: Vec<u8>,
    pub kexinit: Vec<u8>,
}

/// Inputs and algorithm choices for the initial key exchange.
pub struct Transcript {
    pub client: PeerTranscript,
    pub server: PeerTranscript,
    pub kex_algorithm: &'static str,
    pub host_key_algorithm: Algorithm,
    pub packet_algorithms: PacketAlgorithms,
    pub compression: CompressionAlgorithms,
    pub strict_kex: bool,
    /// The peer accepts SSH_MSG_EXT_INFO after initial NEWKEYS.
    pub peer_accepts_ext_info: bool,
    /// SSH receive sequence number for the next packet.
    pub next_receive_sequence: u32,
}

fn lists(preferences: &DirectionPreferences) -> io::Result<(String, String)> {
    let repeated = |values: &[Cipher]| {
        values
            .iter()
            .enumerate()
            .any(|(i, value)| values[..i].contains(value))
    };
    let DirectionPreferences { ciphers, macs } = preferences;
    if ciphers.is_empty()
        || repeated(ciphers)
        || macs
            .iter()
            .enumerate()
            .any(|(i, mac)| macs[..i].contains(mac))
        || (macs.is_empty() && ciphers.iter().any(|cipher| cipher.needs_mac()))
        || (macs.as_slice() == [Mac::None] && ciphers.iter().all(|cipher| cipher.needs_mac()))
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid SSH packet preferences",
        ));
    }
    Ok((
        ciphers
            .iter()
            .map(|cipher| cipher.name())
            .collect::<Vec<_>>()
            .join(","),
        macs.iter()
            .map(|mac| mac.name())
            .collect::<Vec<_>>()
            .join(","),
    ))
}

pub(crate) fn local_proposal(
    role: Role,
    initial_exchange: bool,
    preferences: &TransportPreferences,
    host_algorithms: &[Algorithm],
) -> io::Result<Vec<u8>> {
    let (ciphers_cs, macs_cs) = lists(&preferences.packet.client_to_server)?;
    let (ciphers_sc, macs_sc) = lists(&preferences.packet.server_to_client)?;
    let compression_cs = compression_names(&preferences.compression.client_to_server)?;
    let compression_sc = compression_names(&preferences.compression.server_to_client)?;
    let mut prefix = [0; 17];
    prefix[0] = KEXINIT;
    getrandom::fill(&mut prefix[1..]).map_err(io::Error::other)?;
    let (strict, ext_info) = match role {
        Role::Client => (Kex::StrictClient, Kex::ExtInfoClient),
        Role::Server => (Kex::StrictServer, Kex::ExtInfoServer),
    };
    if !preferences.kex.iter().any(|method| method.is_method())
        || preferences
            .kex
            .iter()
            .enumerate()
            .any(|(index, name)| preferences.kex[..index].contains(name))
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid SSH key exchange preferences",
        ));
    }
    if preferences.kex.contains(&Kex::None)
        && (preferences
            .kex
            .iter()
            .filter(|method| method.is_method())
            .count()
            != 1
            || [
                &preferences.packet.client_to_server,
                &preferences.packet.server_to_client,
            ]
            .into_iter()
            .flat_map(|direction| &direction.ciphers)
            .any(|cipher| !cipher.is_unprotected()))
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "SSH KEX none requires a dedicated clear transport",
        ));
    }
    let kex = preferences
        .kex
        .iter()
        .copied()
        .filter(|method| {
            method.is_method() || (initial_exchange && (*method == strict || *method == ext_info))
        })
        .map(Kex::name)
        .collect::<Vec<_>>()
        .join(",");
    let hosts = host_algorithms
        .iter()
        .map(Algorithm::as_str)
        .collect::<Vec<_>>()
        .join(",");
    let lists = [
        kex.as_str(),
        &hosts,
        &ciphers_cs,
        &ciphers_sc,
        &macs_cs,
        &macs_sc,
        &compression_cs,
        &compression_sc,
        "",
        "",
    ];
    // 17-byte message/cookie, four-byte length per list, then boolean and reserved uint32.
    let mut payload =
        vec![0; 17 + 4 * lists.len() + lists.iter().map(|list| list.len()).sum::<usize>() + 5];
    payload[..17].copy_from_slice(&prefix);
    let mut tail = Writer::new(&mut payload[17..]);
    for list in lists {
        tail.name_list(list).map_err(io::Error::other)?;
    }
    tail.boolean(false).map_err(io::Error::other)?;
    tail.uint32(0).map_err(io::Error::other)?;
    Ok(payload)
}

fn compression_names(preferences: &[Compression]) -> io::Result<String> {
    if preferences.is_empty()
        || preferences.len() > 3
        || preferences
            .iter()
            .enumerate()
            .any(|(index, mode)| !mode.available() || preferences[..index].contains(mode))
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid or disabled SSH compression preferences",
        ));
    }
    Ok(preferences
        .iter()
        .map(|mode| mode.name())
        .collect::<Vec<_>>()
        .join(","))
}

pub(crate) struct Selection {
    pub(crate) algorithm: &'static str,
    pub(crate) host_key_algorithm: Algorithm,
    pub(crate) discard_guess: bool,
    pub(crate) packet_algorithms: PacketAlgorithms,
    pub(crate) selected_macs: [Mac; 2],
    pub(crate) compression: CompressionAlgorithms,
    strict_kex: bool,
    peer_accepts_ext_info: bool,
}

/// Algorithm category in SSH key exchange negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmKind {
    Kex,
    Key,
    Cipher,
    Compression,
    Mac,
}

/// The local and peer algorithm lists had no usable intersection.
#[derive(Debug)]
pub struct NoCommonAlgorithm {
    pub kind: AlgorithmKind,
    pub ours: Vec<String>,
    pub theirs: Vec<String>,
    message: &'static str,
}

impl std::fmt::Display for NoCommonAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for NoCommonAlgorithm {}

fn no_common<'a, T>(
    peer: &str,
    local: &'a [T],
    name: impl Fn(&'a T) -> &'a str,
    kind: AlgorithmKind,
    message: &'static str,
) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        NoCommonAlgorithm {
            kind,
            ours: local.iter().map(|item| name(item).to_owned()).collect(),
            theirs: peer.split_terminator(',').map(str::to_owned).collect(),
            message,
        },
    )
}

fn pick<'a, T>(
    peer: &str,
    role: Role,
    local: &'a [T],
    name: impl Fn(&'a T) -> &'a str,
) -> Option<&'a T> {
    match role {
        Role::Server => peer
            .split(',')
            .find_map(|offered| local.iter().find(|&choice| name(choice) == offered)),
        Role::Client => local
            .iter()
            .find(|&choice| peer.split(',').any(|offered| name(choice) == offered)),
    }
}

fn choose_algorithm<'a, T>(
    peer: &str,
    role: Role,
    local: &'a [T],
    name: impl Fn(&'a T) -> &'a str,
    kind: AlgorithmKind,
    message: &'static str,
) -> io::Result<&'a T> {
    pick(peer, role, local, &name).ok_or_else(|| no_common(peer, local, name, kind, message))
}

fn suite(
    role: Role,
    ciphers: &str,
    macs: &str,
    preferences: &DirectionPreferences,
) -> io::Result<(Suite, Mac)> {
    let cipher = *choose_algorithm(
        ciphers,
        role,
        &preferences.ciphers,
        |cipher| cipher.name(),
        AlgorithmKind::Cipher,
        "no common SSH cipher",
    )?;
    let selected = pick(macs, role, &preferences.macs, |mac| mac.name())
        .copied()
        .unwrap_or(Mac::None);
    let mac = if cipher.needs_mac() {
        if selected == Mac::None {
            return Err(no_common(
                macs,
                &preferences.macs,
                |mac| mac.name(),
                AlgorithmKind::Mac,
                "no common SSH MAC",
            ));
        }
        Some(selected)
    } else {
        None
    };
    Ok((Suite { cipher, mac }, selected))
}

pub(crate) fn choose(
    peer: &[u8],
    role: Role,
    preferences: &TransportPreferences,
    host_algorithms: &[Algorithm],
) -> io::Result<Selection> {
    if peer.first() == Some(&1) {
        // The peer gave up before negotiating and said why; report that.
        return Err(crate::transport::peer_disconnected(peer));
    }
    if peer.first() != Some(&KEXINIT) {
        return Err(ProtocolError::KeyExchangeInit("expected SSH_MSG_KEXINIT").into());
    }
    let mut reader = Reader::new(
        peer.get(17..)
            .ok_or_else(|| invalid("missing KEXINIT cookie"))?,
    );
    let wire_error = |error| io::Error::new(io::ErrorKind::InvalidData, error);
    let mut lists = [""; 8];
    for (index, list) in lists.iter_mut().enumerate() {
        *list = reader.name_list().map_err(wire_error)?;
        if list.is_empty() {
            if index == 4 || index == 5 {
                continue;
            } // AEAD and unprotected ciphers may leave MAC lists empty.
            return Err(invalid("empty KEXINIT algorithm list"));
        }
        if list
            .split(',')
            .any(|name| name.len() > 64 || !name.as_bytes().iter().all(u8::is_ascii_graphic))
        {
            return Err(invalid("invalid KEXINIT algorithm name"));
        }
    }
    for _ in 0..2 {
        reader.name_list().map_err(wire_error)?; // Language preferences.
    }
    let guessed = reader.boolean().map_err(wire_error)?;
    if reader.uint32().map_err(wire_error)? != 0 {
        return Err(invalid("nonzero KEXINIT reserved field"));
    }
    reader.finish().map_err(wire_error)?;

    let [
        kex,
        host_key,
        cipher_cs,
        cipher_sc,
        mac_cs,
        mac_sc,
        compression_cs,
        compression_sc,
    ] = lists;
    let has = |list: &str, name| list.split(',').any(|entry| entry == name);
    let methods = preferences
        .kex
        .iter()
        .copied()
        .filter(|name| name.is_method())
        .collect::<Vec<_>>();
    let algorithm = choose_algorithm(
        kex,
        role,
        &methods,
        |name| name.name(),
        AlgorithmKind::Kex,
        "no common SSH key exchange algorithm",
    )?
    .name();
    let host_key_algorithm = choose_algorithm(
        host_key,
        role,
        host_algorithms,
        Algorithm::as_str,
        AlgorithmKind::Key,
        "no common SSH host key algorithm",
    )?;
    // RFC 4253 section 7: a guess is right only when both sides prefer the
    // same first key exchange and host key algorithms. Comparing the peer's
    // first choice with the negotiated one is not enough: when our first
    // choice is unsupported by the peer, the negotiated algorithm can equal
    // the peer's first choice even though the peer guessed against a different
    // preference and (like OpenSSH) will resend the real exchange packet.
    let wrong_guess = kex.split(',').next() != methods.first().map(|method| method.name())
        || host_key.split(',').next()
            != host_algorithms.first().map(|algorithm| algorithm.as_str());
    let (strict_local, strict_peer, ext_info_peer) = match role {
        Role::Client => (Kex::StrictClient, Kex::StrictServer, Kex::ExtInfoServer),
        Role::Server => (Kex::StrictServer, Kex::StrictClient, Kex::ExtInfoClient),
    };
    let (client_to_server, client_mac) = suite(
        role,
        cipher_cs,
        mac_cs,
        &preferences.packet.client_to_server,
    )?;
    let (server_to_client, server_mac) = suite(
        role,
        cipher_sc,
        mac_sc,
        &preferences.packet.server_to_client,
    )?;
    Ok(Selection {
        algorithm,
        host_key_algorithm: host_key_algorithm.clone(),
        discard_guess: guessed && wrong_guess,
        packet_algorithms: PacketAlgorithms {
            client_to_server,
            server_to_client,
        },
        selected_macs: [client_mac, server_mac],
        compression: CompressionAlgorithms {
            client_to_server: *choose_algorithm(
                compression_cs,
                role,
                &preferences.compression.client_to_server,
                |mode| mode.name(),
                AlgorithmKind::Compression,
                "no common SSH client-to-server compression",
            )?,
            server_to_client: *choose_algorithm(
                compression_sc,
                role,
                &preferences.compression.server_to_client,
                |mode| mode.name(),
                AlgorithmKind::Compression,
                "no common SSH server-to-client compression",
            )?,
        },
        strict_kex: preferences.kex.contains(&strict_local) && has(kex, strict_peer.name()),
        peer_accepts_ext_info: has(kex, ext_info_peer.name()),
    })
}

/// Exchange IDs and KEXINIT on the two halves of a connection. The peer's
/// first packet must be KEXINIT. Returns before the selected method runs.
/// Reuse the same buffered reader for that method. Discard the connection on
/// error or cancellation, and wrap the exchange in a transport deadline.
pub async fn negotiate<R, W>(role: Role, reader: &mut R, writer: &mut W) -> io::Result<Transcript>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    negotiate_with_preferences(
        role,
        reader,
        writer,
        &TransportPreferences::default(),
        &[Algorithm::Ed25519],
    )
    .await
}

pub(crate) async fn negotiate_with_preferences<R, W>(
    role: Role,
    reader: &mut R,
    writer: &mut W,
    preferences: &TransportPreferences,
    host_algorithms: &[Algorithm],
) -> io::Result<Transcript>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let local_kexinit = local_proposal(role, true, preferences, host_algorithms)?;
    let ids =
        identification::exchange_with(role, reader, writer, &identification::Settings::default())
            .await?;
    negotiate_identified(
        role,
        &mut clear_packet::PacketReader::new(reader, None),
        writer,
        ids,
        local_kexinit,
        preferences,
        host_algorithms,
    )
    .await
    .map(|(transcript, _)| transcript)
}

pub(crate) async fn negotiate_identified<R, W>(
    role: Role,
    reader: &mut clear_packet::PacketReader<R>,
    writer: &mut W,
    ids: identification::Ids,
    local_kexinit: Vec<u8>,
    preferences: &TransportPreferences,
    host_algorithms: &[Algorithm],
) -> io::Result<(Transcript, [Mac; 2])>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let receive = async {
        let payload = reader.read().await?;
        let choice = choose(&payload, role, preferences, host_algorithms)?;
        if choice.discard_guess {
            let guess = reader.read().await?;
            if guess[0] == 1 {
                return Err(crate::transport::peer_disconnected(&guess));
            }
            if choice.strict_kex && !(30..=49).contains(&guess[0]) {
                return Err(unexpected_initial_message(
                    guess[0],
                    1,
                    true,
                    "unexpected guessed packet during strict SSH key exchange",
                ));
            }
        }
        Ok((payload, choice))
    };
    let ((), (peer_kexinit, choice)) =
        tokio::try_join!(clear_packet::write(writer, &local_kexinit), receive)?;
    let local = PeerTranscript {
        identification: ids.local,
        kexinit: local_kexinit,
    };
    let peer = PeerTranscript {
        identification: ids.peer,
        kexinit: peer_kexinit,
    };
    let (client, server) = match role {
        Role::Client => (local, peer),
        Role::Server => (peer, local),
    };
    let transcript = Transcript {
        client,
        server,
        kex_algorithm: choice.algorithm,
        host_key_algorithm: choice.host_key_algorithm,
        packet_algorithms: choice.packet_algorithms,
        compression: choice.compression,
        strict_kex: choice.strict_kex,
        peer_accepts_ext_info: choice.peer_accepts_ext_info,
        next_receive_sequence: 1 + u32::from(choice.discard_guess),
    };
    Ok((transcript, choice.selected_macs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::PacketPreferences;
    use crate::keys::HashAlg;

    #[test]
    fn sha1_kex_requires_explicit_preferences_in_either_role() {
        let modern = TransportPreferences::default();
        let hosts = [Algorithm::Ed25519];
        for method in [Kex::DhGroup1Sha1, Kex::DhGroup14Sha1, Kex::DhGexSha1] {
            let legacy = TransportPreferences {
                kex: vec![method],
                ..TransportPreferences::default()
            };
            for (local, remote) in [(Role::Client, Role::Server), (Role::Server, Role::Client)] {
                for initial in [true, false] {
                    let offer = local_proposal(remote, initial, &legacy, &hosts).unwrap();
                    let error = choose(&offer, local, &modern, &hosts).err().unwrap();
                    assert_eq!(error.to_string(), "no common SSH key exchange algorithm");
                    let selected = choose(&offer, local, &legacy, &hosts).unwrap();
                    assert_eq!(selected.algorithm, method.name());
                }
            }
        }
    }

    #[test]
    fn legacy_packet_algorithms_require_explicit_preferences_in_either_role() {
        let modern = TransportPreferences::default();
        let hosts = [Algorithm::Ed25519];
        for (cipher, mac, expected) in [
            (Cipher::Aes128Cbc, Mac::HmacSha256, "no common SSH cipher"),
            #[cfg(feature = "des")]
            (
                Cipher::TripleDesCbc,
                Mac::HmacSha256,
                "no common SSH cipher",
            ),
            (Cipher::Aes128Ctr, Mac::HmacSha1, "no common SSH MAC"),
            (Cipher::Aes128Ctr, Mac::HmacSha1Etm, "no common SSH MAC"),
        ] {
            let direction = DirectionPreferences {
                ciphers: vec![cipher],
                macs: vec![mac],
            };
            let legacy = TransportPreferences {
                packet: PacketPreferences {
                    client_to_server: direction.clone(),
                    server_to_client: direction,
                },
                ..TransportPreferences::default()
            };
            for (local, remote) in [(Role::Client, Role::Server), (Role::Server, Role::Client)] {
                let offer = local_proposal(remote, true, &legacy, &hosts).unwrap();
                assert_eq!(
                    choose(&offer, local, &modern, &hosts)
                        .err()
                        .unwrap()
                        .to_string(),
                    expected
                );
                let selected = choose(&offer, local, &legacy, &hosts).unwrap();
                let chosen = Suite {
                    cipher,
                    mac: Some(mac),
                };
                assert_eq!(selected.packet_algorithms.client_to_server, chosen);
                assert_eq!(selected.packet_algorithms.server_to_client, chosen);
            }
        }
    }

    #[test]
    fn unprotected_ciphers_require_explicit_directional_preferences() {
        let modern = TransportPreferences::default();
        let hosts = [Algorithm::Ed25519];
        for cipher in [Cipher::Clear, Cipher::None] {
            let special = TransportPreferences {
                packet: PacketPreferences {
                    client_to_server: DirectionPreferences {
                        ciphers: vec![cipher],
                        macs: vec![Mac::None],
                    },
                    server_to_client: DirectionPreferences::default(),
                },
                ..TransportPreferences::default()
            };
            for (local, remote) in [(Role::Client, Role::Server), (Role::Server, Role::Client)] {
                for initial in [true, false] {
                    let offer = local_proposal(remote, initial, &special, &hosts).unwrap();
                    let error = choose(&offer, local, &modern, &hosts).err().unwrap();
                    assert_eq!(error.to_string(), "no common SSH cipher");
                    let selected = choose(&offer, local, &special, &hosts).unwrap();
                    assert_eq!(
                        selected.packet_algorithms.client_to_server,
                        Suite { cipher, mac: None }
                    );
                    assert!(selected.packet_algorithms.server_to_client.cipher.is_aead());
                }
            }
        }
    }

    #[test]
    fn none_mac_cannot_be_used_with_ctr_or_cbc() {
        let hosts = [Algorithm::Ed25519];
        for cipher in [Cipher::Aes128Ctr, Cipher::Aes128Cbc] {
            let mut preferences = TransportPreferences::default();
            preferences.packet.client_to_server = DirectionPreferences {
                ciphers: vec![cipher],
                macs: vec![Mac::None],
            };
            let error = local_proposal(Role::Client, true, &preferences, &hosts).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);

            preferences
                .packet
                .client_to_server
                .macs
                .push(Mac::HmacSha256);
            let offer = local_proposal(Role::Client, true, &preferences, &hosts).unwrap();
            let error = choose(&offer, Role::Server, &preferences, &hosts)
                .err()
                .unwrap();
            assert_eq!(error.to_string(), "no common SSH MAC");
        }

        let mut preferences = TransportPreferences::default();
        preferences.packet.client_to_server.macs = vec![Mac::None];
        let offer = local_proposal(Role::Client, true, &preferences, &hosts).unwrap();
        let selected = choose(&offer, Role::Server, &preferences, &hosts).unwrap();
        assert!(selected.packet_algorithms.client_to_server.cipher.is_aead());
        assert_eq!(selected.packet_algorithms.client_to_server.mac, None);
    }

    #[test]
    fn kex_none_cannot_be_a_fallback_or_use_keyed_packet_protection() {
        let hosts = [Algorithm::Ed25519];
        let direction = DirectionPreferences {
            ciphers: vec![Cipher::Clear, Cipher::None],
            macs: vec![Mac::None],
        };
        let plaintext = TransportPreferences {
            kex: vec![Kex::None],
            packet: PacketPreferences {
                client_to_server: direction.clone(),
                server_to_client: direction,
            },
            ..Default::default()
        };
        let modern = TransportPreferences {
            packet: plaintext.packet.clone(),
            ..Default::default()
        };
        for (local, remote) in [(Role::Client, Role::Server), (Role::Server, Role::Client)] {
            for initial in [true, false] {
                let offer = local_proposal(remote, initial, &plaintext, &hosts).unwrap();
                let error = choose(&offer, local, &modern, &hosts).err().unwrap();
                assert_eq!(error.to_string(), "no common SSH key exchange algorithm");
                let choice = choose(&offer, local, &plaintext, &hosts).unwrap();
                assert_eq!(choice.algorithm, Kex::None.name());
            }
        }

        let mut invalid = plaintext.clone();
        invalid.kex.push(Kex::Curve25519);
        let error = local_proposal(Role::Client, true, &invalid, &hosts).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        let mut invalid = plaintext;
        invalid.packet.server_to_client = DirectionPreferences::default();
        let error = local_proposal(Role::Server, false, &invalid, &hosts).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn client_preference_and_guesses_use_the_negotiated_host_algorithm() {
        let preferences = TransportPreferences::default();
        let sha256 = Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        };
        let sha512 = Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        };
        let mut server_offer = local_proposal(
            Role::Server,
            true,
            &preferences,
            &[sha256.clone(), sha512.clone()],
        )
        .unwrap();
        let guess = server_offer.len() - 5;
        server_offer[guess] = 1;

        let client_order = [sha512.clone(), sha256.clone()];
        let choice = choose(&server_offer, Role::Client, &preferences, &client_order).unwrap();
        assert_eq!(choice.host_key_algorithm, sha512);
        assert!(choice.discard_guess);
        let choice = choose(
            &server_offer,
            Role::Client,
            &preferences,
            std::slice::from_ref(&sha256),
        )
        .unwrap();
        assert!(!choice.discard_guess);
        assert!(
            choose(
                &server_offer,
                Role::Client,
                &preferences,
                &[Algorithm::Ed25519]
            )
            .is_err()
        );

        let offer = local_proposal(Role::Client, true, &preferences, &client_order).unwrap();
        let choice = choose(
            &offer,
            Role::Server,
            &preferences,
            &[sha256, sha512.clone()],
        )
        .unwrap();
        assert_eq!(choice.host_key_algorithm, sha512);
    }
}
