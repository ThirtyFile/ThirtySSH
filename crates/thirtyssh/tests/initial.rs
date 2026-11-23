use std::{io::ErrorKind, time::Duration};
use thirtyssh::{
    algorithms::{Cipher, Kex, Mac, Suite},
    clear_packet,
    identification::{LOCAL_ID, Role},
    initial::negotiate,
    wire::Writer,
};
use tokio::{
    io::{self, BufReader},
    time::timeout,
};

const STANDARD: &str = "curve25519-sha256";
const ALIAS: &str = "curve25519-sha256@libssh.org";

fn proposal(kex: &str, server_to_client_cipher: &str, guess: bool) -> Vec<u8> {
    let mut payload = vec![0; 512];
    payload[0] = 20;
    let mut writer = Writer::new(&mut payload[17..]);
    for list in [
        kex,
        "ssh-ed25519",
        "aes128-ctr",
        server_to_client_cipher,
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    ] {
        writer.name_list(list).unwrap();
    }
    writer.boolean(guess).unwrap();
    writer.uint32(0).unwrap();
    let len = 17 + writer.written().len();
    payload.truncate(len);
    payload
}

async fn input(packets: &[&[u8]]) -> Vec<u8> {
    let mut input = b"SSH-2.0-Peer\r\n".to_vec();
    for packet in packets {
        clear_packet::write(&mut input, packet).await.unwrap();
    }
    input
}

#[tokio::test]
async fn two_roles_capture_the_same_transcript_over_short_io() {
    let (client, server) = io::duplex(3);
    let (cr, mut cw) = io::split(client);
    let (sr, mut sw) = io::split(server);
    let (mut cr, mut sr) = (BufReader::new(cr), BufReader::new(sr));
    let (client, server) = timeout(Duration::from_secs(5), async {
        tokio::try_join!(
            negotiate(Role::Client, &mut cr, &mut cw),
            negotiate(Role::Server, &mut sr, &mut sw)
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(client.client.identification, LOCAL_ID);
    assert_eq!(client.server.identification, LOCAL_ID);
    assert_eq!(client.client.kexinit, server.client.kexinit);
    assert_eq!(client.server.kexinit, server.server.kexinit);
    assert_eq!(client.kex_algorithm, Kex::MlKem768X25519Sha256.name());
    assert_eq!(server.kex_algorithm, Kex::MlKem768X25519Sha256.name());
    assert_eq!(client.next_receive_sequence, 1);
    assert_eq!(server.next_receive_sequence, 1);
}

#[tokio::test]
async fn client_preference_and_guessed_packet_rules() {
    let kexinit = proposal(
        &format!("{ALIAS},{STANDARD},ext-info-s"),
        "aes128-ctr",
        true,
    );
    let guess = b"\x1eexample guess";
    let following = b"\x1fexample next";
    let bytes = input(&[&kexinit, guess, following]).await;

    let mut read = bytes.as_slice();
    let server_choice = negotiate(Role::Client, &mut read, &mut io::sink())
        .await
        .unwrap();
    assert_eq!(server_choice.server.kexinit, kexinit);
    assert_eq!(server_choice.kex_algorithm, STANDARD);
    assert_eq!(server_choice.next_receive_sequence, 2);
    assert_eq!(clear_packet::read(&mut read).await.unwrap(), following);

    let mut read = bytes.as_slice();
    let client_choice = negotiate(Role::Server, &mut read, &mut io::sink())
        .await
        .unwrap();
    assert_eq!(client_choice.client.kexinit, kexinit);
    assert_eq!(client_choice.kex_algorithm, ALIAS);
    // The client guessed ALIAS but this server prefers STANDARD. RFC 4253
    // section 7 calls a guess wrong whenever the first preferences differ, so
    // the guessed packet is ignored even though ALIAS ends up negotiated.
    assert_eq!(client_choice.next_receive_sequence, 2);
    assert_eq!(clear_packet::read(&mut read).await.unwrap(), following);

    // When both sides prefer the same first algorithm the guess is right and
    // is the first packet of the exchange.
    let preferred = Kex::MlKem768X25519Sha256.name();
    let agreed = proposal(
        &format!("{preferred},{STANDARD},ext-info-c"),
        "aes128-ctr",
        true,
    );
    let bytes = input(&[&agreed, guess]).await;
    let mut read = bytes.as_slice();
    let choice = negotiate(Role::Server, &mut read, &mut io::sink())
        .await
        .unwrap();
    assert_eq!(choice.kex_algorithm, preferred);
    assert_eq!(choice.next_receive_sequence, 1);
    assert_eq!(clear_packet::read(&mut read).await.unwrap(), guess);
}

#[tokio::test]
async fn malformed_or_unsupported_proposals_fail() {
    let kexinit = proposal(STANDARD, "aes128-ctr", false);
    let mut reserved = kexinit.clone();
    *reserved.last_mut().unwrap() = 1;
    let mut trailing = kexinit.clone();
    trailing.push(1);
    for payload in [
        vec![50],
        kexinit[..16].to_vec(),
        kexinit[..kexinit.len() - 1].to_vec(),
        reserved,
        trailing,
        proposal(
            "ext-info-c,kex-strict-c-v00@openssh.com",
            "aes128-ctr",
            false,
        ),
        proposal(STANDARD, "aes256-cbc", false),
        proposal("has spaces", "aes128-ctr", false),
    ] {
        let bytes = input(&[&payload]).await;
        let error = negotiate(Role::Server, &mut bytes.as_slice(), &mut io::sink())
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn directions_select_independent_protection_and_aead_ignores_mac() {
    let proposal = proposal(STANDARD, "aes256-gcm@openssh.com,aes192-ctr", false);
    let bytes = input(&[&proposal]).await;
    let transcript = negotiate(Role::Server, &mut bytes.as_slice(), &mut io::sink())
        .await
        .unwrap();
    assert_eq!(
        transcript.packet_algorithms.client_to_server,
        Suite {
            cipher: Cipher::Aes128Ctr,
            mac: Some(Mac::HmacSha256)
        }
    );
    assert_eq!(
        transcript.packet_algorithms.server_to_client,
        Suite {
            cipher: Cipher::Aes256Gcm,
            mac: None
        }
    );
}
