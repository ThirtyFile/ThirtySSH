use super::*;
use crate::algorithms::{Cipher, Mac};
use data_encoding::BASE64;

fn keys() -> DirectionKeys {
    DirectionKeys {
        iv: Zeroizing::new(std::array::from_fn(|i| 32 + i as u8)),
        cipher: Zeroizing::new(std::array::from_fn(|i| i as u8)),
        integrity: Zeroizing::new([0x55; 64]),
    }
}

#[tokio::test]
async fn full_size_channel_payload_fits_the_protected_frame() {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    #[derive(Default)]
    struct WriteProbe {
        wire: Vec<u8>,
        writes: usize,
        flushes: usize,
    }

    impl AsyncWrite for WriteProbe {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes += 1;
            self.wire.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let mut payload = vec![0x5a; clear_packet::MAX_CHANNEL_DATA as usize + 13];
    payload[0] = 95;
    for cipher in [
        Cipher::ChaCha20Poly1305,
        Cipher::Aes256Gcm,
        Cipher::Aes128Cbc,
    ] {
        let suite = Suite {
            cipher,
            mac: cipher.needs_mac().then_some(Mac::HmacSha256),
        };
        let mut writer = Direction::new(keys(), suite, Side::Send, 0);
        let mut reader = Direction::new(keys(), suite, Side::Receive, 0);
        let mut probe = WriteProbe::default();
        writer.write(&mut probe, &payload).await.unwrap();
        assert_eq!((probe.writes, probe.flushes), (1, 1));
        assert_eq!(
            reader.read(&mut probe.wire.as_slice()).await.unwrap(),
            payload
        );
        let oversized = vec![0x5a; clear_packet::MAX_TRANSPORT_PACKET_SIZE];
        assert!(writer.write(&mut probe, &oversized).await.is_err());
        assert_eq!((probe.writes, probe.flushes), (1, 1));
    }
}

#[tokio::test]
async fn unprotected_ciphers_use_clear_framing_with_no_tag() {
    for cipher in [Cipher::Clear, Cipher::None] {
        let suite = Suite { cipher, mac: None };
        let mut writer = Direction::new(keys(), suite, Side::Send, 1);
        let mut wire = Vec::new();
        writer.write(&mut wire, b"\x52").await.unwrap();
        writer.write(&mut wire, b"\x5eplain payload").await.unwrap();
        let mut input = wire.as_slice();
        assert_eq!(clear_packet::read(&mut input).await.unwrap(), b"\x52");
        assert_eq!(
            clear_packet::read(&mut input).await.unwrap(),
            b"\x5eplain payload"
        );
        assert!(input.is_empty());
        assert_eq!(writer.sequence, 3);

        let mut input = wire.as_slice();
        let mut reader = Direction::new(keys(), suite, Side::Receive, 1);
        assert_eq!(reader.read(&mut input).await.unwrap(), b"\x52");
        assert_eq!(reader.read(&mut input).await.unwrap(), b"\x5eplain payload");
        assert!(input.is_empty());
        assert_eq!(reader.sequence, 3);
    }
}

#[tokio::test]
async fn unprotected_exchange_consumes_only_one_immediate_newkeys() {
    let suite = Suite {
        cipher: Cipher::Clear,
        mac: None,
    };
    for first in [NEWKEYS, b"\x5efirst application packet"] {
        let mut wire = Vec::new();
        for payload in [first, NEWKEYS, b"\x5elast application packet"] {
            clear_packet::write(&mut wire, payload).await.unwrap();
        }
        let mut reader = Direction::new(keys(), suite, Side::Receive, 1);
        reader.renew_unprotected(suite, Compression::None, false, false);
        let mut stream = wire.as_slice();
        let expected = if first == NEWKEYS { NEWKEYS } else { first };
        assert_eq!(reader.read(&mut stream).await.unwrap(), expected);
        if first != NEWKEYS {
            assert_eq!(reader.read(&mut stream).await.unwrap(), NEWKEYS);
        }
        assert_eq!(
            reader.read(&mut stream).await.unwrap(),
            b"\x5elast application packet"
        );
        assert_eq!(reader.sequence, 4);
    }
}

#[cfg(feature = "flate2")]
#[tokio::test]
async fn unprotected_compression_switches_dictionaries_with_or_without_newkeys() {
    let suite = Suite {
        cipher: Cipher::Clear,
        mac: None,
    };
    let payload = b"\x5eafter the compressor is reset";
    for mode in [Compression::Zlib, Compression::DelayedZlib] {
        let mut sender = Direction::new(keys(), suite, Side::Send, 0);
        let mut receiver = Direction::new(keys(), suite, Side::Receive, 0);
        let mut wire = Vec::new();
        sender.write(&mut wire, NEWKEYS).await.unwrap();
        sender.renew_unprotected(suite, mode, false, false);
        receiver.renew_unprotected(suite, mode, false, false);
        sender.write(&mut wire, payload).await.unwrap();
        let mut input = wire.as_slice();
        assert_eq!(receiver.read(&mut input).await.unwrap(), payload);
        assert!(input.is_empty());

        sender.enable_delayed_compression();
        receiver.enable_delayed_compression();
        for sends_marker in [true, false, true] {
            let mut wire = Vec::new();
            sender.write(&mut wire, payload).await.unwrap();
            sender
                .write(&mut wire, &[crate::initial::KEXINIT])
                .await
                .unwrap();
            if sends_marker {
                sender.write(&mut wire, NEWKEYS).await.unwrap();
            }
            sender.renew_unprotected(suite, mode, true, true);
            sender.write(&mut wire, payload).await.unwrap();

            let mut input = wire.as_slice();
            assert_eq!(receiver.read(&mut input).await.unwrap(), payload);
            assert_eq!(
                receiver.read(&mut input).await.unwrap(),
                [crate::initial::KEXINIT]
            );
            receiver.renew_unprotected(suite, mode, true, true);
            assert_eq!(receiver.read(&mut input).await.unwrap(), payload);
            assert!(input.is_empty());
        }
    }
}

#[cfg(feature = "flate2")]
#[tokio::test]
async fn unprotected_client_does_not_accept_application_data_from_the_prelogin_dictionary() {
    let suite = Suite {
        cipher: Cipher::Clear,
        mac: None,
    };
    let mode = Compression::DelayedZlib;
    let mut sender = Direction::new(keys(), suite, Side::Send, 0);
    let mut receiver = Direction::new(keys(), suite, Side::Receive, 0);
    sender.renew_unprotected(suite, mode, true, false);
    receiver.renew_unprotected(suite, mode, true, false);
    let mut wire = Vec::new();
    sender
        .write(&mut wire, &[crate::auth::SUCCESS])
        .await
        .unwrap();
    sender
        .write(&mut wire, b"\x5estale dictionary")
        .await
        .unwrap();
    let mut stream = wire.as_slice();
    assert_eq!(
        receiver.read(&mut stream).await.unwrap(),
        [crate::auth::SUCCESS]
    );
    receiver.finish_unprotected_userauth(true);
    let error = receiver.read(&mut stream).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "expected SSH_MSG_KEXINIT using previous compression"
    );
}

#[tokio::test]
async fn aead_opens_independent_ssh_packet_vectors() {
    // Generated using Python cryptography 46.0.7 (OpenSSL AESGCM,
    // ChaCha20 and Poly1305). Body begins with pad length 11 and
    // payload 5e414243, followed by padding bytes 0..11. Sequence 7
    // is encoded as a uint64 for ChaCha. The 4-byte length is AAD.
    for (cipher, encoded) in [
        (
            Cipher::Aes128Gcm,
            "AAAAEMurU+bF8HgLuEyK0nbHnXSRQkEAxK2WyytTHMs4BcCI",
        ),
        (
            Cipher::Aes256Gcm,
            "AAAAENlk5zIvmBsMGXhHyMYQ/fNWz1HwJziu9LJvB0BDgrJr",
        ),
        (
            Cipher::ChaCha20Poly1305,
            "o5r8uiMYVAENgytcb2m+9tCH2ibwmIY4UZeu5UNBCo+4YJUQ",
        ),
    ] {
        let packet = BASE64.decode(encoded.as_bytes()).unwrap();
        let suite = Suite { cipher, mac: None };
        let mut opener = Direction::new(keys(), suite, Side::Receive, 7);
        assert_eq!(
            opener.read(&mut packet.as_slice()).await.unwrap(),
            b"\x5eABC",
            "{suite:?}"
        );
        assert_eq!(opener.sequence, 8);
    }
}

#[tokio::test]
async fn cbc_and_sha1_open_independent_chained_ssh_packets() {
    // OpenSSL CBC (Python cryptography 46.0.7) and Python hashlib HMAC.
    // Sequences 7 and 8 use one continuous CBC context. Each frame has
    // ascending padding bytes, and the HMAC key is twenty 0x55 bytes.
    for (cipher, mac, encoded) in [
        (
            Cipher::Aes128Cbc,
            Mac::HmacSha1,
            "nQV22a2uwUR9dyaEQ/XzuEBoKb3FngqhOXDOC65ZBTekLkK99oZHCZhobEtt+keTCj0nT+rjwwo+qNukGvlVVRWyV5k7GRo/8m/LXBQSEGMbpobXjHXFiA==",
        ),
        (
            Cipher::Aes128Cbc,
            Mac::HmacSha1Etm,
            "AAAAEG04bvvKEM/Lh2PDU3mxYePcUORPXmYorHlhyrWmY8mR8sVSLgAAACD9nMJd+tr7p35kTS2z+cpQAbhG5J2Ol2b6/uodPybqc93KZjwZg+Cf1a+iBmMeoGp9jO5z",
        ),
        #[cfg(feature = "des")]
        (
            Cipher::TripleDesCbc,
            Mac::HmacSha1,
            "Sle52udySghS4brZUI5dZ0BoKb3FngqhOXDOC65ZBTekLkK95DsVAaFA8P0GFqI/YEo9QjVrOsxAIAjnrzdhZ7QhffE7GRo/8m/LXBQSEGMbpobXjHXFiA==",
        ),
        #[cfg(feature = "des")]
        (
            Cipher::TripleDesCbc,
            Mac::HmacSha1Etm,
            "AAAAEPtT8Cm3QObTFrgVvvc1rOK4IEpKho5COgvuc/bSXuCAH0NHwgAAABj8ir1gGP7XKf71cH4EBpxwr8ijDeldeqxsBGbw/g1vzVOnvMiX1I4K/GQl9A==",
        ),
    ] {
        let wire = BASE64.decode(encoded.as_bytes()).unwrap();
        let suite = Suite {
            cipher,
            mac: Some(mac),
        };
        let mut opener = Direction::new(keys(), suite, Side::Receive, 7);
        let mut input = wire.as_slice();
        assert_eq!(opener.read(&mut input).await.unwrap(), b"\x5eABC");
        assert_eq!(
            opener.read(&mut input).await.unwrap(),
            b"\x5efollowing packet"
        );
        assert!(input.is_empty());
        assert_eq!(opener.sequence, 9);
        opener.install(keys(), suite, true);
        assert_eq!(opener.sequence, 0);
        assert_eq!(opener.bytes, 0);
        opener.sequence = 7; // The fixture tags start at sequence 7.
        assert_eq!(opener.read(&mut wire.as_slice()).await.unwrap(), b"\x5eABC");
    }
}

const PACKET_LAYOUTS: &[Suite] = &[
    Suite {
        cipher: Cipher::Aes128Ctr,
        mac: Some(Mac::HmacSha256),
    },
    Suite {
        cipher: Cipher::Aes256Ctr,
        mac: Some(Mac::HmacSha512Etm),
    },
    Suite {
        cipher: Cipher::Aes128Gcm,
        mac: None,
    },
    Suite {
        cipher: Cipher::ChaCha20Poly1305,
        mac: None,
    },
    Suite {
        cipher: Cipher::Aes128Cbc,
        mac: Some(Mac::HmacSha1),
    },
    Suite {
        cipher: Cipher::Aes256Cbc,
        mac: Some(Mac::HmacSha1Etm),
    },
    #[cfg(feature = "des")]
    Suite {
        cipher: Cipher::TripleDesCbc,
        mac: Some(Mac::HmacSha1),
    },
    #[cfg(feature = "des")]
    Suite {
        cipher: Cipher::TripleDesCbc,
        mac: Some(Mac::HmacSha1Etm),
    },
];

#[tokio::test]
#[cfg(feature = "des")]
async fn triple_des_etm_accepts_a_short_body_and_pads_for_a_16_byte_probe() {
    let suite = Suite {
        cipher: Cipher::TripleDesCbc,
        mac: Some(Mac::HmacSha1Etm),
    };
    // OpenSSL 3DES-CBC and hashlib HMAC, using an eight-byte body
    // with USERAUTH_SUCCESS and six padding bytes.
    let short = BASE64
        .decode(b"AAAACFbqK6GQJpkqaff0WTSTjkxWVoa4OR+dhmFofHw=")
        .unwrap();
    let mut opener = Direction::new(keys(), suite, Side::Receive, 7);
    assert_eq!(opener.read(&mut short.as_slice()).await.unwrap(), &[52]);

    let mut sealer = Direction::new(keys(), suite, Side::Send, 7);
    let mut wire = Vec::new();
    sealer.write(&mut wire, &[52]).await.unwrap();
    assert_eq!(wire[..LENGTH_SIZE], 16u32.to_be_bytes());
    opener.install(keys(), suite, true);
    opener.sequence = 7;
    assert_eq!(opener.read(&mut wire.as_slice()).await.unwrap(), &[52]);
}

#[tokio::test]
async fn cancelled_reads_preserve_the_prefix_body_and_tag() {
    use std::future::ready;

    for &suite in PACKET_LAYOUTS {
        let mut sealer = Direction::new(keys(), suite, Side::Send, 7);
        let mut opener = Direction::new(keys(), suite, Side::Receive, 7);
        let mut wire = Vec::new();
        let payload = b"\x5eshort read";
        sealer.write(&mut wire, payload).await.unwrap();
        let packet_len = wire.len();
        let frame_len = sealer.bytes;
        let header_len = if opener.layout().separate_length {
            LENGTH_SIZE
        } else {
            opener.layout().block
        };
        sealer
            .write(&mut wire, b"\x5efollowing packet")
            .await
            .unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let mut start = 0;
        for end in [1, header_len, frame_len - 1, frame_len, packet_len - 1] {
            writer.write_all(&wire[start..end]).await.unwrap();
            tokio::select! {
                biased;
                result = opener.read(&mut reader) => panic!("premature completion for {suite:?}: {result:?}"),
                () = ready(()) => {}
            }
            assert_eq!(opener.incoming.filled, end);
            assert_eq!(opener.sequence, 7);
            assert_eq!(opener.bytes, 0);
            start = end;
        }
        writer.write_all(&wire[start..]).await.unwrap();
        drop(writer);
        assert_eq!(opener.read(&mut reader).await.unwrap(), payload);
        assert_eq!(
            opener.read(&mut reader).await.unwrap(),
            b"\x5efollowing packet"
        );
        assert_eq!(opener.sequence, 9);
        assert_eq!(opener.bytes, sealer.bytes);
    }
}

#[tokio::test]
async fn modified_tags_fail_before_delivery_in_each_packet_layout() {
    for &suite in PACKET_LAYOUTS {
        let mut sealer = Direction::new(keys(), suite, Side::Send, u32::MAX);
        let mut output = Vec::new();
        sealer.write(&mut output, b"\x02example").await.unwrap();
        assert_eq!(sealer.sequence, 0);
        *output.last_mut().unwrap() ^= 1;
        let mut opener = Direction::new(keys(), suite, Side::Receive, u32::MAX);
        let error = opener.read(&mut output.as_slice()).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let cause = error.downcast::<ProtocolError>().unwrap();
        if suite.mac.is_some() {
            assert!(matches!(cause, ProtocolError::PacketMac));
        } else {
            assert!(matches!(cause, ProtocolError::Decryption));
        }
        assert_eq!(opener.sequence, u32::MAX);
        assert_eq!(opener.bytes, 0);
    }
}

#[tokio::test]
async fn hard_byte_limit_and_exhausted_gcm_nonce_stop_output() {
    let suite = Suite {
        cipher: Cipher::Aes128Gcm,
        mac: None,
    };
    let mut direction = Direction::new(keys(), suite, Side::Send, 0);
    direction.bytes = KEY_BYTE_LIMIT;
    let mut output = Vec::new();
    assert!(direction.write(&mut output, b"\x02example").await.is_err());
    assert!(output.is_empty());

    direction.install(keys(), suite, true);
    let Protection::Gcm(gcm) = &mut direction.protection else {
        unreachable!()
    };
    gcm.next_iv = Some([0xff; 12]);
    direction.write(&mut output, b"\x02example").await.unwrap();
    let written = output.len();
    assert!(direction.write(&mut output, b"\x02example").await.is_err());
    assert_eq!(output.len(), written);
}

#[test]
fn gcm_authenticates_the_clear_length() {
    let mut frame = Zeroizing::new(
        clear_packet::encode(
            b"\x02example",
            Layout {
                block: 16,
                separate_length: true,
                max_packet_size: clear_packet::MAX_TRANSPORT_PACKET_SIZE,
            },
            0,
        )
        .unwrap(),
    );
    let mut tag = [0; AEAD_TAG];
    let mut sender = Gcm::new(&aead::AES_256_GCM, &keys());
    sender.seal(&mut frame, &mut tag).unwrap();
    frame[3] ^= 16;
    let mut receiver = Gcm::new(&aead::AES_256_GCM, &keys());
    assert_eq!(
        receiver.open(&mut frame, &tag).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn an_impossible_length_is_refused_before_anything_else_is_believed() {
    for &suite in PACKET_LAYOUTS {
        let mut sealer = Direction::new(keys(), suite, Side::Send, u32::MAX);
        let mut output = Vec::new();
        sealer.write(&mut output, b"\x02example").await.unwrap();
        // Every layout here encrypts the length with a stream cipher or sends
        // it in the clear, so this turns it into more than two gigabytes.
        output[0] ^= 0x80;
        let mut opener = Direction::new(keys(), suite, Side::Receive, u32::MAX);
        let error = opener.read(&mut output.as_slice()).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{suite:?}");
        assert!(
            matches!(
                error.downcast::<ProtocolError>().unwrap(),
                ProtocolError::PacketSize { .. }
            ),
            "{suite:?}"
        );
        assert_eq!(opener.sequence, u32::MAX);
        assert_eq!(opener.bytes, 0);
    }
}
