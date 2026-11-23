use std::time::Duration;
#[cfg(feature = "flate2")]
use thirtyssh::transport::HostKey;
use thirtyssh::{
    algorithms::{Compression, CompressionPreferences, TransportPreferences},
    transport::Transport,
};
use tokio::{io, time::timeout};

fn preferences() -> TransportPreferences {
    TransportPreferences {
        compression: CompressionPreferences {
            client_to_server: vec![Compression::Zlib],
            server_to_client: vec![Compression::DelayedZlib],
        },
        ..Default::default()
    }
}

#[tokio::test]
#[cfg(feature = "flate2")]
async fn directional_compression_tracks_auth_success_and_rekey_on_short_io() {
    let host = HostKey::generate().unwrap();
    let (left, right) = io::duplex(3);
    timeout(Duration::from_secs(5), async {
        let (mut client, mut server) = tokio::try_join!(
            Transport::connect_with_preferences(
                left,
                |key| *key == host.public_key(),
                preferences()
            ),
            Transport::accept_with_preferences(right, &host, preferences()),
        )
        .unwrap();
        assert_eq!(
            client.compression_algorithms().client_to_server,
            Compression::Zlib
        );
        assert_eq!(
            server.compression_algorithms().server_to_client,
            Compression::DelayedZlib
        );
        let ((), request) =
            tokio::try_join!(client.send(b"\x05request"), server.receive()).unwrap();
        assert_eq!(request, b"\x05request");
        tokio::try_join!(client.rekey(), server.rekey()).unwrap();
        let (reply, ()) = tokio::try_join!(client.receive(), server.send(&[52])).unwrap();
        assert_eq!(reply, [52]);
        let session = client.session_id().to_vec();
        for pattern in *b"ABC" {
            let mut data = vec![pattern; 32768];
            data[0] = 94;
            let (reply, ()) = tokio::try_join!(client.receive(), server.send(&data)).unwrap();
            assert_eq!(reply, data);
            tokio::try_join!(client.rekey(), server.rekey()).unwrap();
            let ((), reply) = tokio::try_join!(client.send(&data), server.receive()).unwrap();
            assert_eq!(reply, data);
        }
        assert_eq!(client.session_id(), &session);
    })
    .await
    .unwrap();
}

#[tokio::test]
#[cfg(not(feature = "flate2"))]
async fn feature_disabled_rejects_compression_preferences_before_io() {
    let (left, _right) = io::duplex(1);
    let result = timeout(
        Duration::from_secs(1),
        Transport::connect_with_preferences(left, |_| false, preferences()),
    )
    .await
    .unwrap();
    assert_eq!(
        result.err().unwrap().kind(),
        std::io::ErrorKind::InvalidInput
    );
}
