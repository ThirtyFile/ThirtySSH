//! ML-KEM-768 with X25519 as specified by RFC 10042.

use super::{Kex, X25519PrivateKey, invalid, x25519_agree, x25519_keypair};
use ml_kem::{
    B32, Decapsulate, DecapsulationKey, EncapsulationKey, Generate, KeyExport, MlKem768, TryKeyInit,
};
use sha2::{Digest, Sha256};
use std::io;
use zeroize::{Zeroize, Zeroizing};

pub(super) const METHOD: &str = Kex::MlKem768X25519Sha256.name();
const ENCAPSULATION_KEY_BYTES: usize = 1184;
const CIPHERTEXT_BYTES: usize = 1088;
const X25519_BYTES: usize = 32;

pub(super) struct Client {
    mlkem: DecapsulationKey<MlKem768>,
    x25519: X25519PrivateKey,
}

impl Client {
    pub(super) fn generate() -> io::Result<(Self, Vec<u8>)> {
        let mlkem = DecapsulationKey::<MlKem768>::try_generate_from_rng(&mut getrandom::SysRng)
            .map_err(io::Error::other)?;
        let (x25519, public) = x25519_keypair()?;
        let mut field = Vec::with_capacity(ENCAPSULATION_KEY_BYTES + X25519_BYTES);
        field.extend_from_slice(&mlkem.encapsulation_key().to_bytes());
        field.extend_from_slice(public.as_ref());
        Ok((Self { mlkem, x25519 }, field))
    }

    pub(super) fn agree(self, field: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        if field.len() != CIPHERTEXT_BYTES + X25519_BYTES {
            return Err(invalid("invalid SSH hybrid reply length"));
        }
        let (ciphertext, peer) = field.split_at(CIPHERTEXT_BYTES);
        // ML-KEM uses implicit rejection for corrupted ciphertexts of the
        // correct size. The SSH host signature must authenticate the result.
        let shared = Zeroizing::new(
            self.mlkem
                .decapsulate_slice(ciphertext)
                .map_err(|_| invalid("invalid SSH ML-KEM ciphertext length"))?,
        );
        x25519_agree(self.x25519, peer, |classic| combine(&shared, classic))
    }
}

pub(super) fn server_exchange(field: &[u8]) -> io::Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    if field.len() != ENCAPSULATION_KEY_BYTES + X25519_BYTES {
        return Err(invalid("invalid SSH hybrid init length"));
    }
    let (encapsulation_key, peer) = field.split_at(ENCAPSULATION_KEY_BYTES);
    let kem = EncapsulationKey::<MlKem768>::new_from_slice(encapsulation_key)
        .map_err(|_| invalid("invalid SSH ML-KEM encapsulation key"))?;
    let (x25519, public) = x25519_keypair()?;
    x25519_agree(x25519, peer, |classic| {
        let mut entropy = Zeroizing::new(B32::default());
        // Read fresh uniformly random bytes and propagate RNG failure to the
        // connection instead of panicking in an infallible RNG adapter.
        getrandom::fill(entropy.as_mut_slice()).map_err(io::Error::other)?;
        let (ciphertext, shared) = kem.encapsulate_deterministic(&entropy);
        let shared = Zeroizing::new(shared);
        let mut reply = Vec::with_capacity(CIPHERTEXT_BYTES + X25519_BYTES);
        reply.extend_from_slice(&ciphertext);
        reply.extend_from_slice(public.as_ref());
        Ok((reply, combine(&shared, classic)))
    })?
}

fn combine(pq: &[u8], classic: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut hash = Sha256::new();
    hash.update(pq);
    hash.update(classic);
    let mut digest = hash.finalize();
    let secret = Zeroizing::new(digest.to_vec());
    digest.as_mut_slice().zeroize();
    secret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kex::{ED25519, derive, fields, tests::transcript};

    #[test]
    fn hybrid_exchange_agrees_and_generates_fresh_component_keys() {
        let (client, first) = Client::generate().unwrap();
        let (_, second) = Client::generate().unwrap();
        assert_eq!(first.len(), 1216);
        assert_ne!(first[..1184], second[..1184]);
        assert_ne!(first[1184..], second[1184..]);

        let (reply, secret) = server_exchange(&first).unwrap();
        let (next_reply, _) = server_exchange(&first).unwrap();
        assert_eq!(reply.len(), 1120);
        assert_ne!(reply[..1088], next_reply[..1088]);
        assert_ne!(reply[1088..], next_reply[1088..]);
        let combined = client.agree(&reply).unwrap();
        assert_eq!(*combined, *secret);
    }

    #[test]
    fn hybrid_combiner_transcript_and_kdf_match_independent_vectors() {
        // Python hashlib reference with synthetic KEM fields and the
        // RFC 7748 §6.1 X25519 values. K has a high bit or a leading zero,
        // so using mpint anywhere in the hash or KDF changes the results.
        let classic = data_encoding::HEXLOWER_PERMISSIVE
            .decode(b"4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
            .unwrap();
        let mut client = vec![0xa5; 1184];
        client.extend(
            data_encoding::HEXLOWER_PERMISSIVE
                .decode(b"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap(),
        );
        let mut server = vec![0x5a; 1088];
        server.extend(
            data_encoding::HEXLOWER_PERMISSIVE
                .decode(b"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap(),
        );
        let host = fields(None, &[ED25519, &[0x42; 32]]).unwrap();
        let mut transcript = transcript();
        transcript.kex_algorithm = METHOD;
        let vectors = [
            (
                2u16,
                "c250f66c2225a5729f33dc6bc104af59991c61b95092e717d265d8a5b7a7cc33",
                "734e97af31e41efb2559c7f0ddec881a8d73422fb0035543ec92b930d452c6ab",
                "76810b93478acbc5c7cc0114ebc945bfcc9c5e409675eb6a4de4894dca7a4d6c",
                "45f2276f0da006385015b90a7eb46620bcb40dbc022e23b937a20ea0d676bb6c",
            ),
            (
                299,
                "003cd5a61d70c1b109cfa32efb5986056bd5fe1c0ed9503983b0484130bca512",
                "9848094bcbbf730e528fe62bcc4273cfa97ec578a7c59b617f3becb6535f86be",
                "e0289d37cfe2c92de208049974e703fb49228e6a82e269c6c494b61a87b6ef79",
                "ff3b123037fbc900701692622e7c12be6ee0916a1b6c36487e7e22a8f83fbbc3",
            ),
        ];
        for (marker, k, h, first, rekey) in vectors {
            let mut pq = [0u8; 32];
            pq[..2].copy_from_slice(&marker.to_be_bytes());
            let secret = combine(&pq, &classic);
            assert_eq!(data_encoding::HEXLOWER.encode(secret.as_slice()), k);
            for (session, expected) in [(None, first), (Some(&[0x5d; 64][..]), rekey)] {
                let keys = derive(&secret, &transcript, &host, &client, &server, session, None);
                assert_eq!(
                    data_encoding::HEXLOWER.encode(keys.exchange_hash.as_slice()),
                    h
                );
                let c = keys.client_to_server;
                let s = keys.server_to_client;
                let mut digest = Sha256::new();
                for field in [
                    c.iv.as_slice(),
                    c.cipher.as_slice(),
                    &c.integrity[..32],
                    s.iv.as_slice(),
                    &s.cipher[..32],
                    s.integrity.as_slice(),
                ] {
                    digest.update(field);
                }
                assert_eq!(data_encoding::HEXLOWER.encode(&digest.finalize()), expected);
            }
        }
    }
}
