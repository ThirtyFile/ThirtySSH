use super::{encoding_error, invalid};
use p256::elliptic_curve::sec1::ToSec1Point;
use pkcs8::{
    AssociatedOid, ObjectIdentifier,
    der::{
        self, Reader, SliceReader, Tag, TagNumber, Tagged,
        asn1::{AnyRef, BitStringRef, ContextSpecific, OctetStringRef, UintRef},
    },
};
use sec1::{EcParameters, EcPrivateKey};
use sha2::{Digest, Sha256};
use ssh_key::{EcdsaCurve, private::EcdsaKeypair};
use std::io::{self, ErrorKind};

const P256: ObjectIdentifier = p256::NistP256::OID;
const P384: ObjectIdentifier = p384::NistP384::OID;
const P521: ObjectIdentifier = p521::NistP521::OID;
const PRIME_FIELD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.1.1");

// SHA-256 of p, a, b, the uncompressed generator, and n, each preceded by
// its big-endian 32-bit byte length. These are the standard domains emitted
// by openssl ecparam -name P-{256,384,521} -param_enc explicit -outform DER.
const P256_DOMAIN: [u8; 32] = [
    0x46, 0xe3, 0x98, 0x38, 0x34, 0xb2, 0x47, 0xef, 0xca, 0xac, 0xa6, 0x96, 0x17, 0x2e, 0xfb, 0x9f,
    0x16, 0x03, 0x97, 0x34, 0x92, 0xf9, 0x04, 0xe9, 0xd6, 0xff, 0x6b, 0x4f, 0xe4, 0x6f, 0xab, 0x68,
];
const P384_DOMAIN: [u8; 32] = [
    0xed, 0xaa, 0x72, 0xf3, 0xcd, 0x9c, 0x21, 0x0b, 0x4e, 0x98, 0x09, 0x78, 0x2f, 0x54, 0xbc, 0x83,
    0xa2, 0x8d, 0x84, 0xed, 0x8c, 0x20, 0x44, 0x88, 0x29, 0x5f, 0x45, 0xda, 0x36, 0x1c, 0xf0, 0x30,
];
const P521_DOMAIN: [u8; 32] = [
    0x71, 0xa4, 0x88, 0xee, 0x12, 0x96, 0x7f, 0xe1, 0x42, 0x07, 0xe5, 0x29, 0xcc, 0x28, 0x22, 0x55,
    0x8e, 0x6a, 0xa1, 0x6e, 0x2f, 0xc4, 0xcc, 0x23, 0x6a, 0xd5, 0x9d, 0x9c, 0xf7, 0xd8, 0x4a, 0x80,
];

pub(super) fn decode_keypair(
    bytes: &[u8],
    outer_parameters: Option<AnyRef<'_>>,
    outer_public: Option<&[u8]>,
) -> io::Result<EcdsaKeypair> {
    let mut reader = SliceReader::new(bytes).map_err(encoding_error)?;
    let (scalar, parameters, public) = reader
        .sequence(|fields| -> der::Result<_> {
            if fields.decode::<u8>()? != 1 {
                return Err(Tag::Integer.value_error().into());
            }
            let scalar = fields.decode::<&OctetStringRef>()?.as_bytes();
            let parameters = ContextSpecific::<AnyRef>::decode_explicit(fields, TagNumber(0))?
                .map(|params| params.value);
            let public = ContextSpecific::<BitStringRef>::decode_explicit(fields, TagNumber(1))?
                .map(|public| {
                    public
                        .value
                        .as_bytes()
                        .ok_or_else(|| Tag::BitString.value_error())
                })
                .transpose()?;
            Ok((scalar, parameters, public))
        })
        .map_err(encoding_error)?;
    reader.finish().map_err(encoding_error)?;

    let inner_curve = parameters.map(curve_oid).transpose()?;
    let outer_curve = outer_parameters.map(curve_oid).transpose()?;
    let curve = outer_curve
        .or(inner_curve)
        .ok_or_else(|| invalid("missing SEC1 curve parameters"))?;
    if inner_curve.is_some_and(|inner| inner != curve) {
        return Err(invalid("different SEC1 and PKCS#8 curves"));
    }
    build_keypair(curve, scalar, public, outer_public)
}

pub(super) fn keypair_from_scalar(
    curve: EcdsaCurve,
    scalar: &[u8],
    public: &[u8],
) -> io::Result<EcdsaKeypair> {
    let oid = match curve {
        EcdsaCurve::NistP256 => P256,
        EcdsaCurve::NistP384 => P384,
        EcdsaCurve::NistP521 => P521,
    };
    build_keypair(oid, scalar, Some(public), None)
}

fn build_keypair(
    curve: ObjectIdentifier,
    scalar: &[u8],
    public: Option<&[u8]>,
    outer_public: Option<&[u8]>,
) -> io::Result<EcdsaKeypair> {
    let parameters = Some(EcParameters::NamedCurve(curve));
    let key = EcPrivateKey {
        parameters,
        private_key: scalar,
        public_key: public,
    };
    let outer = outer_public.map(|public| EcPrivateKey {
        parameters,
        private_key: scalar,
        public_key: Some(public),
    });
    // RustCrypto validates the point against the private scalar. When both
    // public fields are present, each must match even if encoded differently.
    macro_rules! convert {
        ($curve:ident, $variant:ident) => {{
            if let Some(outer) = outer {
                $curve::SecretKey::try_from(outer).map_err(encoding_error)?;
            }
            let private = $curve::SecretKey::try_from(key).map_err(encoding_error)?;
            Ok(EcdsaKeypair::$variant {
                public: private.public_key().into(),
                private: private.into(),
            })
        }};
    }
    match curve {
        P256 => convert!(p256, NistP256),
        P384 => convert!(p384, NistP384),
        P521 => convert!(p521, NistP521),
        _ => Err(io::Error::new(
            ErrorKind::Unsupported,
            "unsupported SEC1 named curve",
        )),
    }
}

fn curve_oid(parameters: AnyRef<'_>) -> io::Result<ObjectIdentifier> {
    if parameters.tag() == Tag::ObjectIdentifier {
        return parameters
            .decode_as::<ObjectIdentifier>()
            .map_err(encoding_error);
    }
    parameters
        .tag()
        .assert_eq(Tag::Sequence)
        .map_err(encoding_error)?;
    let mut fields = SliceReader::new(parameters.value()).map_err(encoding_error)?;
    if fields
        .decode::<Option<u8>>()
        .map_err(encoding_error)?
        .is_some_and(|version| version != 1)
    {
        return Err(invalid("unsupported explicit EC parameters version"));
    }
    let p = fields
        .sequence(|field| -> der::Result<_> {
            if field.decode::<ObjectIdentifier>()? != PRIME_FIELD {
                return Err(Tag::ObjectIdentifier.value_error().into());
            }
            Ok(field.decode::<UintRef>()?.as_bytes())
        })
        .map_err(encoding_error)?;
    let (a, b) = fields
        .sequence(|curve| -> der::Result<_> {
            let a = curve.decode::<&OctetStringRef>()?.as_bytes();
            let b = curve.decode::<&OctetStringRef>()?.as_bytes();
            // The optional seed describes curve provenance and does not change it.
            curve.decode::<Option<BitStringRef>>()?;
            Ok((a, b))
        })
        .map_err(encoding_error)?;
    let base = fields
        .decode::<&OctetStringRef>()
        .map_err(encoding_error)?
        .as_bytes();
    let order = fields
        .decode::<UintRef>()
        .map_err(encoding_error)?
        .as_bytes();
    let cofactor = fields.decode::<Option<UintRef>>().map_err(encoding_error)?;
    fields.finish().map_err(encoding_error)?;
    if cofactor.is_some_and(|value| value.as_bytes() != [1]) {
        return Err(invalid("unsupported explicit EC cofactor"));
    }
    macro_rules! identify {
        ($curve:ident, $oid:ident, $domain:ident) => {{
            let generator = $curve::PublicKey::from_sec1_bytes(base)
                .map_err(encoding_error)?
                .to_sec1_point(false);
            let mut hasher = Sha256::new();
            for field in [p, a, b, generator.as_bytes(), order] {
                hasher.update((field.len() as u32).to_be_bytes());
                hasher.update(field);
            }
            if hasher.finalize().as_slice() == $domain {
                return Ok($oid);
            }
        }};
    }
    match p.len() {
        32 => identify!(p256, P256, P256_DOMAIN),
        48 => identify!(p384, P384, P384_DOMAIN),
        66 => identify!(p521, P521, P521_DOMAIN),
        _ => {}
    }
    Err(invalid("unsupported explicit EC domain"))
}
