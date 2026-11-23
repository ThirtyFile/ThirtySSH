//! A wire peer with a synthetic context. No Kerberos credentials or platform API is used.
use super::native::{
    transport::{HostKey, Transport},
    wire::Reader,
};
use tokio::io::DuplexStream;

pub const OID: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
pub const USER: &str = "fixture";
pub const FIRST: &[u8] = b"first context token";
pub const PEER: &[u8] = b"peer context token";
pub const LAST: &[u8] = b"final context token";
pub const MIC: &[u8] = b"fixture mic";
pub const STATUS: &str = "fixture GSSAPI error";
pub const ERROR_TOKEN: &[u8] = b"fixture error token";

pub enum Outcome {
    Mic,
    Acknowledge,
    Diagnostics,
    UnofferedMechanism,
    PrematureSuccess,
    ProviderUnavailable,
}

pub fn field(packet: &mut Vec<u8>, value: &[u8]) {
    packet.extend_from_slice(&(value.len() as u32).to_be_bytes());
    packet.extend_from_slice(value);
}

fn message(code: u8, value: &[u8]) -> Vec<u8> {
    let mut packet = vec![code];
    field(&mut packet, value);
    packet
}

pub fn verify_mic_data(packet: &[u8], session_id: &[u8]) {
    let mut reader = Reader::new(packet);
    assert_eq!(reader.string().unwrap(), session_id);
    assert_eq!(reader.byte().unwrap(), 50);
    assert_eq!(reader.string().unwrap(), USER.as_bytes());
    assert_eq!(reader.string().unwrap(), b"ssh-connection");
    assert_eq!(reader.string().unwrap(), b"gssapi-with-mic");
    reader.finish().unwrap();
}

pub async fn serve(
    stream: DuplexStream,
    host: &HostKey,
    outcome: Outcome,
    session_id: tokio::sync::oneshot::Sender<Vec<u8>>,
) {
    let mut transport = Transport::accept(stream, host).await.unwrap();
    session_id.send(transport.session_id().to_vec()).unwrap();
    assert_eq!(
        transport.receive().await.unwrap(),
        message(5, b"ssh-userauth")
    );
    transport.send(&message(6, b"ssh-userauth")).await.unwrap();
    let request = transport.receive().await.unwrap();
    let mut reader = Reader::new(&request);
    assert_eq!(reader.byte().unwrap(), 50);
    assert_eq!(reader.string().unwrap(), USER.as_bytes());
    assert_eq!(reader.string().unwrap(), b"ssh-connection");
    assert_eq!(reader.string().unwrap(), b"gssapi-with-mic");
    assert_eq!(reader.uint32().unwrap(), 1);
    assert_eq!(reader.string().unwrap(), OID);
    reader.finish().unwrap();

    match outcome {
        Outcome::UnofferedMechanism => {
            transport
                .send(&message(60, b"\x06\x02\x2a\x03"))
                .await
                .unwrap();
            return;
        }
        Outcome::PrematureSuccess => {
            transport.send(&[52]).await.unwrap();
            return;
        }
        _ => (),
    }

    transport.send(&message(60, OID)).await.unwrap();
    if matches!(outcome, Outcome::ProviderUnavailable) {
        assert!(transport.receive().await.is_err());
        return;
    }
    assert_eq!(transport.receive().await.unwrap(), message(61, FIRST));
    if matches!(outcome, Outcome::Diagnostics) {
        let mut status = vec![64];
        status.extend_from_slice(&7u32.to_be_bytes());
        status.extend_from_slice(&19u32.to_be_bytes());
        field(&mut status, STATUS.as_bytes());
        field(&mut status, b"en");
        transport.send(&status).await.unwrap();
        transport.send(&message(65, ERROR_TOKEN)).await.unwrap();
        let mut failure = message(51, b"password");
        failure.push(0);
        transport.send(&failure).await.unwrap();

        let fallback = transport.receive().await.unwrap();
        let mut reader = Reader::new(&fallback);
        assert_eq!(reader.byte().unwrap(), 50);
        assert_eq!(reader.string().unwrap(), USER.as_bytes());
        assert_eq!(reader.string().unwrap(), b"ssh-connection");
        assert_eq!(reader.string().unwrap(), b"password");
        assert!(!reader.boolean().unwrap());
        assert_eq!(reader.string().unwrap(), b"fixture fallback");
        reader.finish().unwrap();
    } else {
        transport.send(&message(61, PEER)).await.unwrap();
        assert_eq!(transport.receive().await.unwrap(), message(61, LAST));
        let final_packet = transport.receive().await.unwrap();
        match outcome {
            Outcome::Mic => assert_eq!(final_packet, message(66, MIC)),
            Outcome::Acknowledge => assert_eq!(final_packet, [63]),
            _ => unreachable!(),
        }
    }
    transport.send(&[52]).await.unwrap();
    assert_eq!(transport.receive().await.unwrap()[0], 1);
}
