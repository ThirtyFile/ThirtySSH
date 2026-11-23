use std::io::ErrorKind;
use thirtyssh::clear_packet::{MAX_PACKET_SIZE, read, write};
use tokio::io;

#[tokio::test]
async fn round_trip_keeps_packet_boundaries() {
    let (mut tx, mut rx) = io::duplex(3);
    let big = vec![0x42; MAX_PACKET_SIZE - 9];
    tokio::join!(
        async {
            write(&mut tx, b"\x14").await.unwrap();
            write(&mut tx, &big).await.unwrap();
        },
        async {
            assert_eq!(read(&mut rx).await.unwrap(), b"\x14");
            assert_eq!(read(&mut rx).await.unwrap(), big);
        },
    );
}

#[tokio::test]
async fn rejects_invalid_lengths_without_reading_the_body() {
    for length in [0u32, 4, 11, 13, MAX_PACKET_SIZE as u32, u32::MAX] {
        assert_eq!(
            read(&mut length.to_be_bytes().as_slice())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }
    for padding in [0u8, 3, 11, 255] {
        let header = [0, 0, 0, 12, padding];
        assert_eq!(
            read(&mut header.as_slice()).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }
}

#[tokio::test]
async fn truncated_frame_and_invalid_outbound_length_are_errors() {
    let mut frame = Vec::new();
    write(&mut frame, b"\x14").await.unwrap();
    assert_eq!(
        u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
        frame.len() - 4
    );
    assert_eq!(frame.len(), 16);
    assert_eq!(frame[4], 10);
    assert_eq!(frame[5], 20);
    for end in 0..frame.len() {
        assert_eq!(
            read(&mut &frame[..end]).await.unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }
    let oversized = vec![0; MAX_PACKET_SIZE - 8];
    for payload in [&[][..], oversized.as_slice()] {
        assert_eq!(
            write(&mut frame, payload).await.unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }
    assert_eq!(frame.len(), 16);
}
