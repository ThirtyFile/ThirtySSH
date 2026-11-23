use super::{PrivateKey, encoding_error, invalid};
use pkcs8::{
    AlgorithmIdentifierRef,
    der::{
        self, Decode, Reader, SliceReader, Tag, TagNumber,
        asn1::{BitStringRef, ContextSpecific, OctetStringRef},
    },
};
use ssh_key::private::Ed25519Keypair;
use std::io;

pub(super) fn decode(bytes: &[u8]) -> io::Result<PrivateKey> {
    // This legacy encoding wraps the public key in EXPLICIT [1] and nests
    // the seed and public key in a single OCTET STRING.
    let mut reader = SliceReader::new(bytes).map_err(encoding_error)?;
    let (private, public) = reader
        .sequence(|fields| -> der::Result<_> {
            if fields.decode::<u8>()? != 1 {
                return Err(Tag::Integer.value_error().into());
            }
            let id = fields.decode::<AlgorithmIdentifierRef<'_>>()?;
            if id.oid != ed25519::pkcs8::ALGORITHM_OID || id.parameters.is_some() {
                return Err(Tag::ObjectIdentifier.value_error().into());
            }
            let private = fields.decode::<&OctetStringRef>()?;
            let private = <&OctetStringRef>::from_der(private.as_bytes())?.as_bytes();
            let public = ContextSpecific::<BitStringRef>::decode_explicit(fields, TagNumber(1))?
                .and_then(|bits| bits.value.as_bytes())
                .ok_or_else(|| Tag::BitString.value_error())?;
            Ok((private, public))
        })
        .map_err(encoding_error)?;
    reader.finish().map_err(encoding_error)?;

    let (seed, embedded) = private
        .split_first_chunk::<32>()
        .ok_or_else(|| invalid("incomplete legacy Ed25519 seed"))?;
    let pair = Ed25519Keypair::from_seed(seed);
    if public != pair.public.0 || (!embedded.is_empty() && embedded != pair.public.0) {
        return Err(invalid("inconsistent legacy Ed25519 keypair"));
    }
    PrivateKey::new(pair.into(), "").map_err(encoding_error)
}
