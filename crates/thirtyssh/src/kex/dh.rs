use super::{modp, positive_mpint};
use crate::{algorithms::Kex, clear_packet::invalid, wire::validate_mpint};
use crypto_bigint::{
    BoxedUint, CtEq, Limb, Odd,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use std::{
    io,
    sync::{Arc, OnceLock},
};
use zeroize::Zeroizing;

struct FixedGroup {
    method: Kex,
    prime: &'static [u8],
    random_bytes: usize,
    parameters: OnceLock<Arc<Group>>,
}

impl FixedGroup {
    const fn new(method: Kex, prime: &'static [u8], random_bytes: usize) -> Self {
        Self {
            method,
            prime,
            random_bytes,
            parameters: OnceLock::new(),
        }
    }

    fn parameters(&self) -> &Arc<Group> {
        self.parameters.get_or_init(|| {
            let bits = (self.prime.len() * 8) as u32;
            let prime = BoxedUint::from_be_slice_truncated(self.prime, bits);
            let prime = Odd::new(prime).expect("fixed MODP prime is odd");
            let upper = prime.wrapping_sub(Limb::ONE);
            let generator = BoxedUint::from_be_slice_truncated(&[2], bits);
            Arc::new(Group {
                params: BoxedMontyParams::new_vartime(prime),
                generator,
                upper,
                random_bytes: self.random_bytes,
            })
        })
    }
}

// Groups 14–18 exceed the larger exponent entropy estimate in RFC 3526 §8.
static GROUPS: [FixedGroup; 6] = [
    FixedGroup::new(Kex::DhGroup14Sha256, modp::GROUP14, 41),
    FixedGroup::new(Kex::DhGroup15Sha512, modp::GROUP15, 53),
    FixedGroup::new(Kex::DhGroup16Sha512, modp::GROUP16, 61),
    FixedGroup::new(Kex::DhGroup17Sha512, modp::GROUP17, 68),
    FixedGroup::new(Kex::DhGroup18Sha512, modp::GROUP18, 78),
    FixedGroup::new(Kex::DhGroup1Sha1, modp::GROUP1, 32),
];

pub(super) struct Group {
    params: BoxedMontyParams,
    generator: BoxedUint,
    upper: BoxedUint,
    random_bytes: usize,
}

impl Group {
    pub(super) fn fixed(method: &str) -> Option<Arc<Self>> {
        let method = if method == Kex::DhGroup14Sha1.name() {
            Kex::DhGroup14Sha256.name()
        } else {
            method
        };
        GROUPS
            .iter()
            .find(|group| group.method.name() == method)
            .map(FixedGroup::parameters)
            .cloned()
    }

    pub(super) fn known_prime(prime: &[u8]) -> Option<Arc<Self>> {
        GROUPS
            .iter()
            .find(|group| group.prime == prime)
            .map(|group| group.parameters().clone())
    }

    pub(super) fn from_mpints(
        prime: &[u8],
        generator: &[u8],
        sizes: std::ops::RangeInclusive<u32>,
    ) -> io::Result<Arc<Self>> {
        let bytes = unsigned_mpint(prime)?;
        let bits = bytes
            .first()
            .map_or(0, |first| (bytes.len() * 8) as u32 - first.leading_zeros());
        if !sizes.contains(&bits) {
            return Err(invalid(
                "SSH GEX modulus outside requested and supported sizes",
            ));
        }
        let prime = BoxedUint::from_be_slice_truncated(bytes, bits);
        let upper = prime.wrapping_sub(Limb::ONE);
        let generator = bounded_public(generator, &upper)?;
        if let Some(group) = Self::known_prime(bytes) {
            if generator == group.generator {
                return Ok(group);
            }
        } else if !crypto_primes::is_prime(crypto_primes::Flavor::Safe, &prime) {
            return Err(invalid("SSH GEX modulus is not a safe prime"));
        }
        let prime = Odd::new(prime)
            .into_option()
            .ok_or_else(|| invalid("even SSH GEX modulus"))?;
        Ok(Arc::new(Self {
            params: BoxedMontyParams::new_vartime(prime),
            generator,
            upper,
            random_bytes: 80,
        }))
    }

    pub(super) fn mpints(&self) -> (Vec<u8>, Vec<u8>) {
        (
            positive_mpint(&self.params.modulus().to_be_bytes()),
            positive_mpint(&self.generator.to_be_bytes()),
        )
    }

    pub(super) fn bit_size(&self) -> u32 {
        self.params.modulus().bit_width_vartime()
    }

    pub(super) fn decode_peer(&self, encoded: &[u8]) -> io::Result<BoxedUint> {
        bounded_public(encoded, &self.upper)
    }
}

fn unsigned_mpint(encoded: &[u8]) -> io::Result<&[u8]> {
    let bytes = validate_mpint(encoded)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(invalid("negative SSH DH value"));
    }
    Ok(bytes.strip_prefix(&[0]).unwrap_or(bytes))
}

fn bounded_public(encoded: &[u8], upper: &BoxedUint) -> io::Result<BoxedUint> {
    let value = BoxedUint::from_be_slice(unsigned_mpint(encoded)?, upper.bits_precision())
        .map_err(|_| invalid("oversized SSH DH peer public value"))?;
    if value <= BoxedUint::one() || value >= *upper {
        return Err(invalid("SSH DH peer public value outside (1, p-1)"));
    }
    Ok(value)
}

pub(super) struct Key {
    group: Arc<Group>,
    exponent: Zeroizing<BoxedUint>,
}

impl Key {
    pub(super) fn generate(group: Arc<Group>) -> io::Result<(Self, Vec<u8>)> {
        // A fixed top bit puts the exponent above 1 and well below (p-1)/2.
        // The remaining bits are independent of the peer and uniformly random.
        let mut bytes = Zeroizing::new(vec![0; group.random_bytes + 1]);
        bytes[0] = 1;
        getrandom::fill(&mut bytes[1..]).map_err(io::Error::other)?;
        let bits = (group.random_bytes * 8 + 1) as u32;
        let exponent = Zeroizing::new(BoxedUint::from_be_slice_truncated(&bytes, bits));
        Ok(Self::with_exponent(group, exponent))
    }

    fn with_exponent(group: Arc<Group>, exponent: Zeroizing<BoxedUint>) -> (Self, Vec<u8>) {
        let generator = group.generator.clone();
        let key = Self { group, exponent };
        let public = key.pow(generator).to_be_bytes();
        (key, positive_mpint(&public))
    }

    pub(super) fn agree(self, encoded: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let peer = self.group.decode_peer(encoded)?;
        self.agree_validated(peer)
    }

    pub(super) fn agree_validated(self, peer: BoxedUint) -> io::Result<Zeroizing<Vec<u8>>> {
        let secret = self.pow(peer);
        if (secret.is_zero() | secret.is_one() | secret.ct_eq(&self.group.upper)).into() {
            return Err(invalid("degenerate SSH DH shared secret"));
        }
        Ok(Zeroizing::new(secret.to_be_bytes().into_vec()))
    }

    fn pow(&self, base: BoxedUint) -> Zeroizing<BoxedUint> {
        let base = BoxedMontyForm::new(base, &self.group.params);
        // pow uses a loop bound from the fixed precision, independent of the exponent value.
        let result = Zeroizing::new(base.pow(&self.exponent));
        Zeroizing::new(result.retrieve())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kex::{self, ED25519, tests::transcript};
    use sha2::{Digest, Sha256};

    #[test]
    fn fixed_groups_match_independent_exchange_hash_and_kdf_vectors() {
        // Python pow() and hashlib using the RFC 2409 and RFC 3526 primes. Each vector
        // supplies H and a SHA-256 digest of all six expanded key fields.
        let expected = [
            (
                Kex::DhGroup14Sha256,
                "e49c24aa46b87d87b8924da410a052e4a84036f1c7bc14e5e839c882825348b9",
                "2903f892b2c6f5d6e12f44f7c51583c04d8c0b68c497a0637074709ab5408168",
            ),
            (
                Kex::DhGroup15Sha512,
                concat!(
                    "0210b021a9b571df319c9dd53682ab1e61d2a10f779e2a7c8cee4912119188cc0",
                    "86325cff6be5a04160ebd2b915e70e0efff922145a4721de066c25d5b442e37",
                ),
                "261095bebd32306914e5f128fb37177377573959134d6bd499e8ebc35aa1fe98",
            ),
            (
                Kex::DhGroup16Sha512,
                concat!(
                    "1ad8bf491918e080ee252f47b237f8762339df07ec2d5b9b12d8e944dbf1a813a7",
                    "5734a2a18038187f76126f5a1dfd642f42241504000f508bbb47c917400c52",
                ),
                "87a291b79ae6dece40974a019f228d8e523169f1737bf7e3d95576fda9f2d73d",
            ),
            (
                Kex::DhGroup17Sha512,
                concat!(
                    "a09f8d41b9536cdde76247f51627c321ec3deaf51da1a61a264e3d9c90f8a520",
                    "6217d922ac9784248c0bd1ae5f5e83f25c70d90ae05b99a380f44a25f03ca744",
                ),
                "9b416ee4900b5ab2282b7f7961e6283935baa62fe82ee4f6b0110854be64e8fc",
            ),
            (
                Kex::DhGroup18Sha512,
                concat!(
                    "29e23dd051aa2d74a58bd8d6dcba6388c51c171321cb4181176a244ba9d4ea74f",
                    "35ba5644a244da44100e17dc0df0a9bb7b108c8616eb180f4a6ba326fd08907",
                ),
                "9600e4139889ade795cd4a9092d8c7a7cfb2b7ac90c2374ca61ffd07a806868c",
            ),
            (
                Kex::DhGroup1Sha1,
                "c47ad5a4ab4dac20fba42fe96ac20c457574f1a3",
                "248dce71251ad062d1460f0de7f462f5f5394e5e62ba522cb72e583d30ef3179",
            ),
            (
                Kex::DhGroup14Sha1,
                "dca1c52ccb1400238c59ee237b1c7ba440037798",
                "db5b11e9ea54d43d192cae3a8d398f59fd467ad44cbf62a61c32e2e575cff942",
            ),
        ];
        for (method, hash, digest) in expected {
            let params = Group::fixed(method.name()).unwrap();
            let exponent = |hex| Zeroizing::new(BoxedUint::from_be_hex(hex, 128).unwrap());
            let (client, e) =
                Key::with_exponent(params.clone(), exponent("0102030405060708090a0b0c0d0e0f10"));
            let (server, f) =
                Key::with_exponent(params.clone(), exponent("cba987654312feea22334455dd678901"));
            let server_secret = server.agree(&e).unwrap();
            let client_secret = client.agree(&f).unwrap();
            assert_eq!(*server_secret, *client_secret);
            let mut transcript = transcript();
            transcript.kex_algorithm = method.name();
            let host = kex::fields(None, &[ED25519, &[0x42; 32]]).unwrap();
            let keys = kex::derive(
                &client_secret,
                &transcript,
                &host,
                &e,
                &f,
                Some(&[0x5d; 48]),
                None,
            );
            assert_eq!(
                keys.exchange_hash.as_slice(),
                data_encoding::HEXLOWER_PERMISSIVE
                    .decode(hash.as_bytes())
                    .unwrap(),
                "{}",
                method.name()
            );
            let client = keys.client_to_server;
            let server = keys.server_to_client;
            let mut output = Sha256::new();
            for key in [
                client.iv.as_slice(),
                client.cipher.as_slice(),
                &client.integrity[..32],
                server.iv.as_slice(),
                &server.cipher[..32],
                server.integrity.as_slice(),
            ] {
                output.update(key);
            }
            assert_eq!(
                output.finalize().as_slice(),
                data_encoding::HEXLOWER_PERMISSIVE
                    .decode(digest.as_bytes())
                    .unwrap(),
                "{}",
                method.name()
            );
        }
    }

    #[test]
    fn fixed_groups_reject_noncanonical_and_out_of_range_peer_values() {
        for group in &GROUPS {
            let group = group.parameters();
            let upper = positive_mpint(&group.upper.to_be_bytes());
            let prime = positive_mpint(&group.params.modulus().to_be_bytes());
            let oversized =
                positive_mpint(&vec![1; (group.params.bits_precision() / 8 + 1) as usize]);
            for invalid in [
                &[][..],
                &[0],
                &[1],
                &[0x80],
                &[0, 2],
                &upper,
                &prime,
                &oversized,
            ] {
                assert_eq!(
                    group.decode_peer(invalid).unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            }
            let inside = group.upper.wrapping_sub(Limb::ONE);
            assert_eq!(
                group
                    .decode_peer(&positive_mpint(&inside.to_be_bytes()))
                    .unwrap(),
                inside
            );
            assert_eq!(group.decode_peer(&[2]).unwrap(), group.generator);
        }
    }

    #[test]
    fn invalid_dh_public_value_fails_in_both_wire_roles() {
        let mut transcript = transcript();
        let host = kex::HostSigner::Ed25519(kex::HostKey::from_seed(&[0x42; 32]).unwrap());
        let init = kex::fields(Some(kex::KEX_METHOD_INIT), &[&[1]]).unwrap();
        let blob = host.public_blob().unwrap();
        let reply =
            kex::fields(Some(kex::KEX_METHOD_REPLY), &[&blob, &[1], b"unused proof"]).unwrap();
        for method in [Kex::DhGroup14Sha256, Kex::DhGroup1Sha1, Kex::DhGroup14Sha1] {
            transcript.kex_algorithm = method.name();
            let err = kex::server_reply(&init, &transcript, &host, None, None)
                .err()
                .unwrap();
            assert_eq!(err.to_string(), "SSH DH peer public value outside (1, p-1)");
            let (client, _) = kex::ClientExchange::start(method.name()).unwrap();
            let err = client
                .finish(&reply, &transcript, None, Default::default())
                .err()
                .unwrap();
            assert_eq!(err.to_string(), "SSH DH peer public value outside (1, p-1)");
        }
    }
}
