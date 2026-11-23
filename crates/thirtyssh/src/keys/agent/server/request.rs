use super::{
    super::protocol::{
        ADD_CONSTRAINED, ADD_IDENTITY, CONSTRAIN_CONFIRM, CONSTRAIN_LIFETIME, EXTENSION,
        EXTENSION_RESPONSE, LOCK, REMOVE_ALL, REMOVE_IDENTITY, REQUEST_IDENTITIES, RSA_SHA256,
        RSA_SHA512, SIGN_REQUEST, UNLOCK, protocol,
    },
    Operation,
};
use crate::{
    keys::{Algorithm, HashAlg, PrivateKey, agent::Error, ssh_key::private::KeypairData},
    runtime::Instant,
    wire::Reader,
};
use ssh_encoding::{Decode, Encode};
use std::{str, sync::Arc, time::Duration};

pub(super) enum Request<'a> {
    List,
    Add(PendingIdentity),
    Remove(&'a [u8]),
    RemoveAll,
    Sign {
        blob: &'a [u8],
        data: &'a [u8],
        flags: u32,
    },
    Lock(&'a [u8]),
    Unlock(&'a [u8]),
    Query,
}

pub(super) struct Identity {
    pub key: Arc<PrivateKey>,
    pub confirm: bool,
    pub expires: Option<Instant>,
}

pub(super) struct PendingIdentity {
    key: Arc<PrivateKey>,
    confirm: bool,
    lifetime: Option<u32>,
}

impl PendingIdentity {
    pub(super) fn install(self) -> Result<(Vec<u8>, Identity), Error> {
        let blob = self.key.public_key().to_bytes()?;
        let expires = self
            .lifetime
            .map(|seconds| {
                Instant::now()
                    .checked_add(Duration::from_secs(u64::from(seconds)))
                    .ok_or(Error::Refused)
            })
            .transpose()?;
        Ok((
            blob,
            Identity {
                key: self.key,
                confirm: self.confirm,
                expires,
            },
        ))
    }
}

impl Request<'_> {
    pub(super) fn parse(packet: &[u8]) -> Result<Request<'_>, Error> {
        let mut reader = Reader::new(packet);
        let code = reader.byte().map_err(protocol)?;
        let request = match code {
            REQUEST_IDENTITIES => Request::List,
            ADD_IDENTITY | ADD_CONSTRAINED => {
                return parse_identity(reader.remaining(), code == ADD_CONSTRAINED);
            }
            REMOVE_IDENTITY => Request::Remove(reader.string().map_err(protocol)?),
            REMOVE_ALL => Request::RemoveAll,
            SIGN_REQUEST => Request::Sign {
                blob: reader.string().map_err(protocol)?,
                data: reader.string().map_err(protocol)?,
                flags: reader.uint32().map_err(protocol)?,
            },
            LOCK => {
                let password = reader.string().map_err(protocol)?;
                if password.is_empty() {
                    return Err(Error::Refused);
                }
                Request::Lock(password)
            }
            UNLOCK => Request::Unlock(reader.string().map_err(protocol)?),
            EXTENSION if reader.string().map_err(protocol)? == b"query" => Request::Query,
            _ => return Err(Error::Refused),
        };
        reader.finish().map_err(protocol)?;
        Ok(request)
    }

    pub(super) fn operation(&self) -> Option<Operation> {
        Some(match self {
            Request::List => Operation::ListIdentities,
            Request::Add(_) => Operation::AddIdentity,
            Request::Remove(_) => Operation::RemoveIdentity,
            Request::RemoveAll => Operation::RemoveAllIdentities,
            Request::Sign { .. } => Operation::Sign,
            Request::Lock(_) => Operation::Lock,
            Request::Unlock(_) => Operation::Unlock,
            Request::Query => return None,
        })
    }
}

impl Identity {
    pub(super) fn signature_algorithm(&self, flags: u32) -> Result<Algorithm, Error> {
        match (self.key.algorithm(), flags) {
            (Algorithm::Rsa { .. }, RSA_SHA256) => Ok(Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            }),
            (Algorithm::Rsa { .. }, RSA_SHA512) => Ok(Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            }),
            (Algorithm::Rsa { .. }, 0) => Ok(crate::keys::RSA_SHA1),
            (Algorithm::Rsa { .. }, _) => Err(Error::Refused),
            (algorithm, 0) => Ok(algorithm),
            _ => Err(Error::Refused),
        }
    }
}

fn parse_identity(mut payload: &[u8], constrained: bool) -> Result<Request<'_>, Error> {
    let key = KeypairData::decode(&mut payload)?;
    let mut reader = Reader::new(payload);
    let comment = str::from_utf8(reader.string().map_err(protocol)?).map_err(protocol)?;
    let mut confirm = false;
    let mut lifetime = None;
    if constrained {
        while !reader.remaining().is_empty() {
            match reader.byte().map_err(protocol)? {
                CONSTRAIN_CONFIRM => confirm = true,
                CONSTRAIN_LIFETIME => {
                    let seconds = reader.uint32().map_err(protocol)?;
                    lifetime = Some(lifetime.map_or(seconds, |current: u32| current.min(seconds)));
                }
                _ => return Err(Error::Refused),
            }
        }
    }
    reader.finish().map_err(protocol)?;
    let key = PrivateKey::new(key, comment)?;
    // The same limits as a key read from a file. Without them a client could
    // store a key whose every signature occupies a signing slot for minutes,
    // or one that signs under a public key it does not belong to.
    crate::keys::format::validate_keypair(&key).map_err(|_| Error::Refused)?;
    let key = Arc::new(key);
    Ok(Request::Add(PendingIdentity {
        key,
        confirm,
        lifetime,
    }))
}

pub(super) fn query_reply() -> Result<Vec<u8>, Error> {
    let mut reply = vec![EXTENSION_RESPONSE];
    "query".encode(&mut reply)?;
    "query".encode(&mut reply)?;
    Ok(reply)
}
