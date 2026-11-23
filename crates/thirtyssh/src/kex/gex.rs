//! RFC 4419 group exchange, with RFC 8270 modulus bounds.

use super::{decode, dh::Group, fields, positive_mpint};
use crate::{clear_packet::invalid, wire::Reader};
use sha2::Digest;
use std::{future::Future, io, pin::Pin, sync::Arc};
use tokio::sync::Mutex;

pub(crate) const REQUEST: u8 = 34;
pub(crate) const GROUP: u8 = 31;
pub(crate) const INIT: u8 = 32;
pub(crate) const REPLY: u8 = 33;
const MINIMUM_BITS: u32 = 2048;
const MAXIMUM_BITS: u32 = 8192;

pub(crate) fn is_method(method: &str) -> bool {
    matches!(
        method,
        "diffie-hellman-group-exchange-sha1" | "diffie-hellman-group-exchange-sha256"
    )
}

/// The modulus sizes, in bits, a client asks a group-exchange server for: the
/// smallest and largest it accepts, and the one it would like.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GexSizes {
    minimum: u32,
    preferred: u32,
    maximum: u32,
}

impl GexSizes {
    pub fn new(minimum: u32, preferred: u32, maximum: u32) -> io::Result<Self> {
        if !(MINIMUM_BITS..=preferred).contains(&minimum) || preferred > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSH GEX client sizes must satisfy 2048 <= minimum <= preferred <= maximum",
            ));
        }
        Ok(Self {
            minimum,
            preferred,
            maximum,
        })
    }

    pub fn minimum(&self) -> u32 {
        self.minimum
    }

    pub fn preferred(&self) -> u32 {
        self.preferred
    }

    pub fn maximum(&self) -> u32 {
        self.maximum
    }

    pub(crate) fn request(self) -> [u8; 13] {
        let mut packet = [REQUEST; 13];
        for (field, bits) in packet[1..].as_chunks_mut::<4>().0.iter_mut().zip([
            self.minimum,
            self.preferred,
            self.maximum,
        ]) {
            field.copy_from_slice(&bits.to_be_bytes());
        }
        packet
    }

    fn from_request(request: &[u8]) -> io::Result<Self> {
        let mut reader = Reader::new(request);
        let map = |error| io::Error::new(io::ErrorKind::InvalidData, error);
        if reader.byte().map_err(map)? != REQUEST {
            return Err(invalid("expected SSH GEX request"));
        }
        let minimum = reader.uint32().map_err(map)?;
        let preferred = reader.uint32().map_err(map)?;
        let maximum = reader.uint32().map_err(map)?;
        reader.finish().map_err(map)?;
        Self::from_peer_request(minimum, preferred, maximum)
    }

    fn from_peer_request(minimum: u32, preferred: u32, maximum: u32) -> io::Result<Self> {
        if minimum > preferred || preferred > maximum || maximum < MINIMUM_BITS {
            return Err(invalid("invalid SSH GEX peer size request"));
        }
        Ok(Self {
            minimum,
            preferred,
            maximum,
        })
    }

    pub(super) fn sizes(self) -> std::ops::RangeInclusive<u32> {
        self.minimum.max(MINIMUM_BITS)..=self.maximum.min(MAXIMUM_BITS)
    }
}

impl Default for GexSizes {
    fn default() -> Self {
        Self {
            minimum: 3072,
            preferred: 8192,
            maximum: 8192,
        }
    }
}

/// Validated parameters for a finite-field group offered by a GEX server.
#[derive(Clone)]
pub struct GexGroup(Arc<Group>);

impl GexGroup {
    /// Validate an unsigned big-endian safe prime and generator.
    pub fn from_components(prime: &[u8], generator: &[u8]) -> io::Result<Self> {
        Group::from_mpints(
            &positive_mpint(prime),
            &positive_mpint(generator),
            MINIMUM_BITS..=MAXIMUM_BITS,
        )
        .map(Self)
    }

    /// Select a built-in group that fits the request.
    pub fn builtin(parameters: GexSizes) -> Option<Self> {
        super::modp::default_gex_prime(parameters)
            .and_then(Group::known_prime)
            .map(Self)
    }

    /// The size of the group's modulus.
    pub fn bits(&self) -> u32 {
        self.0.bit_size()
    }
}

type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Option<GexGroup>>> + Send>>;

/// A server's asynchronous GEX group lookup, invoked for each exchange.
#[derive(Clone)]
pub struct GexGroupLookup {
    lookup: Arc<dyn Fn(GexSizes) -> LookupFuture + Send + Sync>,
    pub(crate) rekey_gate: Option<Arc<Mutex<()>>>,
}

impl GexGroupLookup {
    pub fn new<F, R>(lookup: F) -> Self
    where
        F: Fn(GexSizes) -> R + Send + Sync + 'static,
        R: Future<Output = io::Result<Option<GexGroup>>> + Send + 'static,
    {
        Self {
            lookup: Arc::new(move |parameters| Box::pin(lookup(parameters))),
            rekey_gate: None,
        }
    }

    /// Serialize rekey with other callbacks that use the same application state.
    /// The transport can continue sending old-key application packets while the gate is held.
    pub fn serialize_rekey_with(mut self, gate: Arc<Mutex<()>>) -> Self {
        self.rekey_gate = Some(gate);
        self
    }
}

/// Retains the bytes that the host proof must bind to the exchange.
pub(crate) struct Exchange {
    request: [u8; 13],
    group_packet: Vec<u8>,
    pub(super) group: Arc<Group>,
}

impl Exchange {
    pub(crate) async fn server(
        request: &[u8],
        lookup: Option<&GexGroupLookup>,
    ) -> io::Result<Self> {
        let parameters = GexSizes::from_request(request)?;
        let selected = match lookup {
            Some(lookup) => (lookup.lookup)(parameters).await?,
            None => GexGroup::builtin(parameters),
        };
        let GexGroup(group) =
            selected.ok_or_else(|| invalid("no SSH DH group fits the peer's request"))?;
        if !parameters.sizes().contains(&group.bit_size()) {
            return Err(invalid(
                "SSH GEX lookup returned a group outside requested sizes",
            ));
        }
        let (prime, generator) = group.mpints();
        let group_packet = fields(Some(GROUP), &[&prime, &generator])?;
        Ok(Self {
            request: parameters.request(),
            group_packet,
            group,
        })
    }

    /// Validate the server's group. Proving that a 3072 to 8192 bit modulus is
    /// a safe prime takes from milliseconds to seconds depending on the build,
    /// so the check runs on a blocking thread and does not stall the runtime.
    pub(crate) async fn client(parameters: GexSizes, group_packet: Vec<u8>) -> io::Result<Self> {
        #[cfg(not(target_family = "wasm"))]
        {
            tokio::task::spawn_blocking(move || Self::client_blocking(parameters, group_packet))
                .await
                .map_err(io::Error::other)?
        }
        #[cfg(target_family = "wasm")]
        {
            Self::client_blocking(parameters, group_packet)
        }
    }

    fn client_blocking(parameters: GexSizes, group_packet: Vec<u8>) -> io::Result<Self> {
        let [prime, generator] = decode(&group_packet, Some(GROUP))?;
        let group = Group::from_mpints(prime, generator, parameters.sizes())?;
        Ok(Self {
            request: parameters.request(),
            group_packet,
            group,
        })
    }

    pub(crate) fn group_packet(&self) -> &[u8] {
        &self.group_packet
    }

    pub(super) fn hash(&self, hash: &mut impl Digest) {
        hash.update(&self.request[1..]);
        hash.update(&self.group_packet[1..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        algorithms::{Kex, TransportPreferences},
        auth::Method,
        kex::{ED25519, derive, positive_mpint, tests::transcript},
        keys::{Algorithm, Credential},
    };
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[test]
    fn exchange_proof_binds_request_and_modulus() {
        let bounds = GexSizes::new(2048, 3072, 4096).unwrap();
        let group = Group::fixed(Kex::DhGroup14Sha256.name()).unwrap();
        let (p, g) = group.mpints();
        let group =
            Exchange::client_blocking(bounds, fields(Some(GROUP), &[&p, &g]).unwrap()).unwrap();
        let host = fields(None, &[ED25519, &[0x42; 32]]).unwrap();
        let mut transcript = transcript();
        // Independently calculated with Python hashlib, using g=2, x=5, y=7.
        for (method, hash, key) in [
            (
                Kex::DhGexSha256,
                "fa0a5d76abe0114bfa232ca3372dd7cc0b9166d27eb18e880b340546d08db05f",
                concat!(
                    "2979d5ef5d44e3f5d4dc3682cc56c5e2514986a6212a9be96aee2f6c32f9debaa",
                    "c7453a68c764426533023b363012608986ffd2379ecf240b5bc8f37b6319b5b"
                ),
            ),
            (
                Kex::DhGexSha1,
                "46c43bc2bfef9e23059e42fe63343138d0faca8a",
                concat!(
                    "bd3aa6280e90930b051107c5ee9f9690147a6c81497a790ccfd55886913c32b6675",
                    "21439727e45088451a09198905056a7b92a899ee3bb4164ba60d758d2820f"
                ),
            ),
        ] {
            transcript.kex_algorithm = method.name();
            let keys = derive(
                &2u64.pow(35).to_be_bytes(),
                &transcript,
                &host,
                &[32],
                &[0, 128],
                Some(&[0x5d; 64]),
                Some(&group),
            );
            assert_eq!(
                data_encoding::HEXLOWER.encode(keys.exchange_hash.as_slice()),
                hash,
                "{method:?}"
            );
            assert_eq!(
                data_encoding::HEXLOWER.encode(keys.client_to_server.cipher.as_slice()),
                key,
                "{method:?}"
            );
        }
    }

    #[tokio::test]
    async fn builtin_lookup_respects_both_bounds() {
        for bits in [2048, 4096] {
            let bounds = GexSizes::new(bits, bits, bits).unwrap();
            let exchange = Exchange::server(&bounds.request(), None).await.unwrap();
            Exchange::client_blocking(bounds, exchange.group_packet().to_vec()).unwrap();
        }
        let bounds = GexSizes::new(3072, 3072, 3072).unwrap();
        assert!(Exchange::server(&bounds.request(), None).await.is_err());
        let invalid = GexSizes {
            minimum: 4096,
            preferred: 2048,
            maximum: 8192,
        };
        assert!(Exchange::server(&invalid.request(), None).await.is_err());
        let mut truncated = GexSizes::default().request().to_vec();
        truncated.pop();
        assert!(Exchange::server(&truncated, None).await.is_err());
    }

    #[test]
    fn builtin_group_is_the_smallest_that_reaches_the_preferred_size() {
        let chosen = |minimum, preferred, maximum| {
            let sizes = GexSizes::new(minimum, preferred, maximum).unwrap();
            crate::kex::modp::default_gex_prime(sizes).map(|prime| prime.len() * 8)
        };
        assert_eq!(chosen(2048, 2048, 8192), Some(2048));
        assert_eq!(chosen(2048, 3072, 8192), Some(4096));
        assert_eq!(chosen(2048, 4096, 8192), Some(4096));
        // Nothing reaches the preferred size: the largest group, not the smallest.
        assert_eq!(chosen(2048, 8192, 8192), Some(4096));
    }

    #[tokio::test]
    async fn custom_lookup_cannot_bypass_bounds_or_fall_back() {
        let parameters = GexSizes::new(3072, 3072, 3072).unwrap();
        let incorrect = GexGroup(Group::fixed(Kex::DhGroup14Sha256.name()).unwrap());
        let lookup = GexGroupLookup::new(move |_| std::future::ready(Ok(Some(incorrect.clone()))));
        let error = Exchange::server(&parameters.request(), Some(&lookup))
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "SSH GEX lookup returned a group outside requested sizes"
        );

        // This request has a built-in match. A custom lookup may still reject it.
        let parameters = GexSizes::new(2048, 2048, 2048).unwrap();
        let lookup = GexGroupLookup::new(|_| std::future::ready(Ok(None)));
        assert!(
            Exchange::server(&parameters.request(), Some(&lookup))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn server_config_uses_custom_lookup_again_after_authentication() {
        use crate::{client, server, session, transport::HostKey};

        struct Allowed;
        impl server::AuthPolicy for Allowed {
            async fn password(&mut self, user: &str, password: &[u8]) -> io::Result<bool> {
                Ok(user == "fixture" && password == b"fixture-pass")
            }
        }
        impl session::Handler for Allowed {}

        struct Trust([u8; 32]);
        impl session::Handler for Trust {}
        impl client::Handler for Trust {
            async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
                let Some(key) = host.ed25519() else {
                    return Ok(false);
                };
                Ok(self.0 == key)
            }
        }

        tokio::time::timeout(Duration::from_secs(10), async {
            let key = HostKey::generate().unwrap();
            let trust = Trust(key.public_key());
            let mut server_config = server::Config::new(key);
            server_config.preferred.kex = vec![Kex::DhGexSha256, Kex::StrictServer];
            let parameters = GexSizes::new(3072, 3072, 3072).unwrap();
            let (p, g) = Group::fixed(Kex::DhGroup15Sha512.name()).unwrap().mpints();
            let group = GexGroup::from_components(&p, &g).unwrap();
            assert_eq!(group.bits(), 3072);
            let calls = Arc::new(AtomicUsize::new(0));
            server_config.gex_group_lookup = Some(GexGroupLookup::new({
                let calls = calls.clone();
                move |observed| {
                    assert_eq!(observed, parameters);
                    calls.fetch_add(1, Ordering::Relaxed);
                    std::future::ready(Ok(Some(group.clone())))
                }
            }));
            let client_config = client::Config {
                preferred: TransportPreferences {
                    kex: vec![Kex::DhGexSha256, Kex::StrictClient],
                    gex: parameters,
                    ..Default::default()
                },
                ..Default::default()
            };
            let (left, right) = tokio::io::duplex(8192);
            let accept = async {
                server::accept_over(Arc::new(server_config), left, None, Allowed)
                    .await
                    .unwrap()
                    .await
                    .unwrap();
            };
            let connect = async {
                let mut client = client::connect_over(Arc::new(client_config), right, trust)
                    .await
                    .unwrap();
                assert_eq!(calls.load(Ordering::Relaxed), 1);
                assert!(
                    client
                        .authenticate("fixture", Method::Password("fixture-pass"))
                        .await
                        .unwrap()
                        .is_accepted()
                );
                let client = client.start().unwrap();
                let handle = client.handle();
                handle.rekey().await.unwrap();
                assert_eq!(calls.load(Ordering::Relaxed), 2);
                handle.ping().await.unwrap();
                client.disconnect().await.unwrap();
            };
            tokio::join!(accept, connect);
        })
        .await
        .unwrap();
    }

    #[test]
    fn client_validates_custom_primes_generators_and_size_before_key_generation() {
        // RFC 7919 A.1 safe prime, distinct from the RFC 3526 MODP groups.
        let custom = data_encoding::HEXLOWER_PERMISSIVE
            .decode(
                concat!(
                    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695",
                    "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A",
                    "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935",
                    "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A",
                    "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4",
                    "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61",
                    "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005",
                    "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF",
                )
                .as_bytes(),
            )
            .unwrap();
        let prime = positive_mpint(&custom);
        let bounds = GexSizes::new(2048, 2048, 2048).unwrap();
        let packet = |p, g| fields(Some(GROUP), &[p, g]).unwrap();
        let group = Exchange::client_blocking(bounds, packet(&prime, &[2])).unwrap();
        assert_eq!(group.group.mpints(), (prime.clone(), vec![2]));
        // OpenSSL-generated prime p with p mod 12 = 7, so (p-1)/2 is divisible by 3.
        let non_safe = data_encoding::HEXLOWER_PERMISSIVE
            .decode(
                concat!(
                    "EE736737EC12F6FFC76A6C95BDB9B29A4D07A9A626B98381D6DEF84E5292B346",
                    "CA1F5A4B582CB371CD5FEE127BA2E80C1222A560C7B9FA9DDB71D7DFFD67A8D0",
                    "A4C6D9BDACE42E102C34F5D116DB9FC32BC23AAC8CA1F761DD4C8DC89F93FCDC",
                    "DD53D6B636C5A85F079F8CB47157261C6C301630C82845CA8A52C851F4D1EC34",
                    "0239E89068DC405CA7F8D84E2C57C938E4A831294DBEB397BB52753C7F1E922B",
                    "53FC9972642B2B6A976F81B499244A93B2BE58B9BCD95882060B9C44194F7F19",
                    "C024F3275A1CE5CB9E677D3C799677C117D0AEFF0CA969F7E4284C0049A08DD3",
                    "B09C805EB84C1388F43E85695C09586000770FD0493F6C14F6225A71F0BE7DEF",
                )
                .as_bytes(),
            )
            .unwrap();
        for (invalid_prime, generator) in [
            (prime.as_slice(), &[1][..]),
            (prime.as_slice(), &[0x80][..]),
            (&positive_mpint(&non_safe), &[2][..]),
            (&positive_mpint(&[0xff; 256]), &[2][..]),
            (&positive_mpint(&[0xff; 1025]), &[2][..]),
            (&[0x7f][..], &[2][..]),
        ] {
            assert!(Exchange::client_blocking(bounds, packet(invalid_prime, generator)).is_err());
        }
    }
}
