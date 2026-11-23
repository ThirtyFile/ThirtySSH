use std::{io::ErrorKind, time::Duration};
use thirtyssh::identification::{LOCAL_ID, Role, exchange};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn two_peers_exchange_ids_over_one_byte_buffers() {
    let (client, server) = io::duplex(1);
    let (cr, mut cw) = io::split(client);
    let (sr, mut sw) = io::split(server);
    let (mut cr, mut sr) = (BufReader::new(cr), BufReader::new(sr));
    let (peer_at_client, peer_at_server) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(
            exchange(Role::Client, &mut cr, &mut cw),
            exchange(Role::Server, &mut sr, &mut sw)
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(peer_at_client, LOCAL_ID);
    assert_eq!(peer_at_server, LOCAL_ID);
}

#[tokio::test]
async fn greeting_preserves_exact_id_and_the_next_binary_bytes() {
    let input = b"first line\r\nsecond line\nSSH-2.0-Peer_1 comment  with spaces\r\n\x00\xff\x03";
    let mut reader = BufReader::new(&input[..]);
    let mut writes = Vec::new();
    let peer = exchange(Role::Client, &mut reader, &mut writes)
        .await
        .unwrap();
    assert_eq!(peer, b"SSH-2.0-Peer_1 comment  with spaces");
    assert_eq!(writes, [LOCAL_ID, b"\r\n"].concat());
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, [0, 255, 3]);
}

async fn receive(role: Role, mut input: &[u8]) -> std::io::Result<Vec<u8>> {
    exchange(role, &mut input, &mut io::sink()).await
}

#[tokio::test]
async fn version_and_role_validation() {
    for id in [&b"SSH-1.99-Peer\n"[..], b"SSH-1.99-Peer\r\n"] {
        assert_eq!(receive(Role::Client, id).await.unwrap(), b"SSH-1.99-Peer");
        assert_eq!(
            receive(Role::Server, id).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }
    for input in [
        &b"SSH-1.5-Peer\r\n"[..],
        b"SSH-2.0- no software\r\n",
        b"SSH-2.0-a-b\r\n",
        b"SSH-2.0-a\t\r\n",
        b"SSH-2.0-peer\n",
        b"SSH-2.0-peer c\0x\r\n",
        b"greeting\nSSH-1.99-peer\n",
        b"SSH-bad\r\nSSH-2.0-good\r\n",
    ] {
        assert_eq!(
            receive(Role::Client, input).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }
    assert_eq!(
        receive(Role::Server, b"greeting\nSSH-2.0-peer\r\n")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(
        receive(Role::Client, b"SSH-2.0-peer\r")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn line_and_greeting_limits_include_terminators() {
    let mut line = b"SSH-2.0-".to_vec();
    line.resize(253, b'a');
    line.extend_from_slice(b"\r\n");
    assert_eq!(receive(Role::Client, &line).await.unwrap(), &line[..253]);
    line.insert(8, b'a');
    assert_eq!(
        receive(Role::Client, &line).await.unwrap_err().kind(),
        ErrorKind::InvalidData
    );
    let mut greeting = vec![b'x'; 8191];
    greeting.extend_from_slice(b"\nSSH-2.0-peer\r\n");
    assert_eq!(
        receive(Role::Client, &greeting).await.unwrap(),
        b"SSH-2.0-peer"
    );
    greeting.insert(0, b'x');
    assert_eq!(
        receive(Role::Client, &greeting).await.unwrap_err().kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(
        receive(Role::Client, &[b'x'; 8500])
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn full_unterminated_id_is_rejected_while_peer_is_still_connected() {
    let (mut peer, stream) = io::duplex(255);
    let mut line = b"SSH-2.0-".to_vec();
    line.resize(255, b'a');
    peer.write_all(&line).await.unwrap();
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        exchange(Role::Client, &mut BufReader::new(stream), &mut io::sink()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidData);
}
