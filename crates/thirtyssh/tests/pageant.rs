#![cfg(windows)]

use std::time::Duration;
use thirtyssh::keys::agent::Client;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

#[tokio::test]
#[ignore = "requires an isolated, empty Pageant instance on the Windows desktop"]
async fn enumerates_identities_through_a_real_pageant_named_pipe() {
    timeout(Duration::from_secs(4), async {
        let mut agent = Client::pageant().await.unwrap();
        assert!(agent.identities().await.unwrap().is_empty());
        assert!(agent.identities().await.unwrap().is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated, empty Pageant instance on the Windows desktop"]
async fn enumerates_identities_through_a_real_pageant_window() {
    timeout(Duration::from_secs(4), async {
        let mut stream = pageant::Pageant::connect_over(pageant::Transport::WindowMessage)
            .await
            .unwrap();
        stream.write_all(&[0, 0]).await.unwrap();
        stream.write_all(&[0, 1]).await.unwrap();
        stream.write_all(&[11]).await.unwrap();
        let mut response = [0; 9];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0, 0, 0, 5, 12, 0, 0, 0, 0]);
        let mut agent = Client::new(stream);
        assert!(agent.identities().await.unwrap().is_empty());
    })
    .await
    .unwrap();
}
