use super::{
    PrivateKey, PrivateKeyLimits, decode_canonical_public_key, ec, encoding_error, invalid,
    key_is_encrypted, malformed, validate_dsa_keypair,
};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use data_encoding::{BASE64, HEXLOWER_PERMISSIVE};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use ssh_key::{
    Cipher, Mpint,
    private::{DsaKeypair, DsaPrivateKey, Ed25519Keypair, KeypairData},
    public::KeyData,
};
use std::io::{self, ErrorKind};
use zeroize::Zeroizing;
#[cfg(feature = "rsa")]
use {
    super::{MAX_RSA_BITS, rsa_private_key},
    ssh_key::private::{RsaKeypair, RsaPrivateKey},
};

use crate::wire::Reader;

pub(super) const HEADER_PREFIX: &str = "PuTTY-User-Key-File-";

#[derive(Clone, Copy)]
enum PpkVersion {
    V2,
    V3,
}

pub(super) fn decode_ppk(
    contents: &str,
    password: Option<&str>,
    limits: PrivateKeyLimits,
) -> io::Result<PrivateKey> {
    // PuTTY accepts LF, CRLF and CR. The section line counts count base64
    // records, so empty lines do not supply input bytes.
    let mut lines = contents
        .split_terminator(['\n', '\r'])
        .filter(|line| !line.is_empty());
    let first = lines
        .next()
        .and_then(|line| line.strip_prefix(HEADER_PREFIX))
        .and_then(|line| line.split_once(": "))
        .ok_or_else(|| invalid("invalid PPK header"))?;
    let (version, algorithm) = match first {
        ("2", algorithm) => (PpkVersion::V2, algorithm),
        ("3", algorithm) => (PpkVersion::V3, algorithm),
        _ => {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "unsupported PPK version",
            ));
        }
    };
    if (!cfg!(feature = "rsa") && algorithm == "ssh-rsa")
        || !matches!(
            algorithm,
            "ssh-ed25519"
                | "ssh-dss"
                | "ssh-rsa"
                | "ecdsa-sha2-nistp256"
                | "ecdsa-sha2-nistp384"
                | "ecdsa-sha2-nistp521"
        )
    {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "unsupported PPK key algorithm",
        ));
    }
    let encryption = field(&mut lines, "Encryption")?;
    let encrypted = match encryption {
        "none" => false,
        "aes256-cbc" => true,
        _ => {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "unsupported PPK encryption",
            ));
        }
    };
    let comment = field(&mut lines, "Comment")?;
    let public_bytes = blob(&mut lines, "Public-Lines", contents.len())?;
    let public = decode_canonical_public_key(&public_bytes)?;
    if public.algorithm().as_str() != algorithm {
        return Err(invalid(
            "PPK public key does not match the header algorithm",
        ));
    }
    let argon2 = if matches!(version, PpkVersion::V3) && encrypted {
        Some(ppk_argon2(&mut lines, limits)?)
    } else {
        None
    };
    let mut private = blob(&mut lines, "Private-Lines", contents.len())?;
    let mac = field(&mut lines, "Private-MAC")?;
    if lines.next().is_some() {
        return Err(invalid("unexpected data after PPK MAC"));
    }
    let mut tag = [0u8; 32];
    let tag_len = match version {
        PpkVersion::V2 => 20,
        PpkVersion::V3 => 32,
    };
    if HEXLOWER_PERMISSIVE.decode_len(mac.len()) != Ok(tag_len) {
        return Err(invalid("invalid PPK MAC length"));
    }
    HEXLOWER_PERMISSIVE
        .decode_mut(mac.as_bytes(), &mut tag[..tag_len])
        .map_err(|error| encoding_error(error.error))?;
    let password = if encrypted {
        if private.is_empty() || !private.len().is_multiple_of(16) {
            return Err(invalid("invalid PPK ciphertext length"));
        }
        password.ok_or_else(key_is_encrypted)?
    } else {
        ""
    };

    // v3 derives cipher key, IV and MAC key in a single Argon2 operation.
    let mut material = Zeroizing::new([0u8; 80]);
    let mac_key = match (version, argon2) {
        (PpkVersion::V2, _) => {
            if encrypted {
                let first = Zeroizing::new(
                    Sha1::new()
                        .chain_update(0u32.to_be_bytes())
                        .chain_update(password)
                        .finalize(),
                );
                let second = Zeroizing::new(
                    Sha1::new()
                        .chain_update(1u32.to_be_bytes())
                        .chain_update(password)
                        .finalize(),
                );
                material[..20].copy_from_slice(&first);
                material[20..32].copy_from_slice(&second[..12]);
            }
            let key = Zeroizing::new(
                Sha1::new()
                    .chain_update(b"putty-private-key-file-mac-key")
                    .chain_update(password)
                    .finalize(),
            );
            material[48..68].copy_from_slice(&key);
            &material[48..68]
        }
        (PpkVersion::V3, Some((algorithm, params, salt))) => {
            let mut blocks = Zeroizing::new(Vec::new());
            blocks
                .try_reserve_exact(params.block_count())
                .map_err(io::Error::other)?;
            blocks.resize(params.block_count(), Block::default());
            Argon2::new(algorithm, Version::V0x13, params)
                .hash_password_into_with_memory(
                    password.as_bytes(),
                    &salt,
                    &mut material[..],
                    &mut *blocks,
                )
                .map_err(encoding_error)?;
            &material[48..]
        }
        (PpkVersion::V3, None) => &[],
    };
    if encrypted {
        Cipher::Aes256Cbc
            .decrypt(&material[..32], &material[32..48], &mut private, None)
            .map_err(encoding_error)?;
    }
    let fields = [
        algorithm.as_bytes(),
        encryption.as_bytes(),
        comment.as_bytes(),
        &public_bytes,
        &private,
    ];
    let tag = &tag[..tag_len];
    let verified = match version {
        PpkVersion::V2 => verify_mac(
            <Hmac<Sha1> as KeyInit>::new_from_slice(mac_key),
            fields,
            tag,
        ),
        PpkVersion::V3 => verify_mac(
            <Hmac<Sha256> as KeyInit>::new_from_slice(mac_key),
            fields,
            tag,
        ),
    };
    if !verified {
        return Err(io::Error::new(
            if encrypted {
                ErrorKind::PermissionDenied
            } else {
                ErrorKind::InvalidData
            },
            "PPK MAC verification failed",
        ));
    }
    let mut reader = Reader::new(&private);
    let data = decode_private(public.key_data(), &mut reader)?;
    if reader.remaining().len() >= 16 || (!encrypted && !reader.remaining().is_empty()) {
        return Err(invalid("unexpected trailing PPK private key bytes"));
    }
    PrivateKey::new(data, comment).map_err(encoding_error)
}

fn field<'a>(lines: &mut impl Iterator<Item = &'a str>, name: &str) -> io::Result<&'a str> {
    match lines.next().and_then(|line| line.split_once(": ")) {
        Some((actual, value)) if actual == name => Ok(value),
        _ => Err(invalid("missing or misplaced PPK field")),
    }
}

fn blob<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    name: &str,
    capacity: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let count = field(lines, name)?
        .parse::<usize>()
        .map_err(encoding_error)?;
    if count == 0 || count > capacity {
        return Err(invalid("invalid PPK base64 line count"));
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
    for _ in 0..count {
        encoded.extend_from_slice(
            lines
                .next()
                .ok_or_else(|| invalid("truncated PPK base64 data"))?
                .as_bytes(),
        );
    }
    let decoded_len = BASE64.decode_len(encoded.len()).map_err(encoding_error)?;
    let mut decoded = Zeroizing::new(vec![0; decoded_len]);
    let len = BASE64
        .decode_mut(&encoded, &mut decoded)
        .map_err(|error| encoding_error(error.error))?;
    decoded.truncate(len);
    Ok(decoded)
}

fn ppk_argon2<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    limits: PrivateKeyLimits,
) -> io::Result<(Algorithm, Params, Vec<u8>)> {
    let algorithm = match field(lines, "Key-Derivation")? {
        "Argon2d" => Algorithm::Argon2d,
        "Argon2i" => Algorithm::Argon2i,
        "Argon2id" => Algorithm::Argon2id,
        _ => {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "unsupported PPK KDF",
            ));
        }
    };
    let memory: u32 = field(lines, "Argon2-Memory")?
        .parse()
        .map_err(encoding_error)?;
    let passes: u32 = field(lines, "Argon2-Passes")?
        .parse()
        .map_err(encoding_error)?;
    let parallelism: u32 = field(lines, "Argon2-Parallelism")?
        .parse()
        .map_err(encoding_error)?;
    if memory > limits.max_argon2_memory_kib
        || u64::from(memory) * u64::from(passes) > limits.max_argon2_work
        || parallelism > limits.max_argon2_parallelism
    {
        return Err(invalid("PPK Argon2 cost exceeds the configured limit"));
    }
    let salt = field(lines, "Argon2-Salt")?;
    if !(16..=2048).contains(&salt.len()) {
        return Err(invalid("invalid PPK Argon2 salt length"));
    }
    let salt = HEXLOWER_PERMISSIVE
        .decode(salt.as_bytes())
        .map_err(encoding_error)?;
    let params = Params::new(memory, passes, parallelism, Some(80)).map_err(encoding_error)?;
    Ok((algorithm, params, salt))
}

fn verify_mac<T: Mac>(
    mac: Result<T, hmac::digest::InvalidLength>,
    fields: [&[u8]; 5],
    tag: &[u8],
) -> bool {
    let Ok(mut mac) = mac else { return false };
    for field in fields {
        mac.update(&(field.len() as u32).to_be_bytes());
        mac.update(field);
    }
    mac.verify_slice(tag).is_ok()
}

fn unsigned<'a>(reader: &mut Reader<'a>) -> io::Result<&'a [u8]> {
    let value = reader.mpint().map_err(malformed)?;
    if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(invalid("negative PPK private component"));
    }
    Ok(value.strip_prefix(&[0]).unwrap_or(value))
}

fn decode_private(public: &KeyData, reader: &mut Reader<'_>) -> io::Result<KeypairData> {
    match public {
        KeyData::Dsa(public) => {
            let private = DsaPrivateKey::new(Mpint::from_positive_bytes(unsigned(reader)?))
                .map_err(encoding_error)?;
            let pair = DsaKeypair::new(public.clone(), private).map_err(encoding_error)?;
            validate_dsa_keypair(&pair)?;
            Ok(pair.into())
        }
        KeyData::Ed25519(point) => {
            // PuTTYgen writes the 32-byte seed directly, including its
            // high bit. Also accept the positive mpint representation.
            let mut wire = Reader::new(reader.remaining());
            let raw = wire.string().map_err(malformed)?;
            let scalar = if raw.len() == 32 {
                *reader = wire;
                raw
            } else {
                unsigned(reader)?
            };
            let mut seed = Zeroizing::new([0u8; 32]);
            let start = seed
                .len()
                .checked_sub(scalar.len())
                .ok_or_else(|| invalid("invalid PPK Ed25519 private component"))?;
            seed[start..].copy_from_slice(scalar);
            let pair = Ed25519Keypair::from_seed(&seed);
            if pair.public != *point {
                return Err(invalid("inconsistent PPK Ed25519 keypair"));
            }
            Ok(pair.into())
        }
        KeyData::Ecdsa(point) => {
            Ok(
                ec::keypair_from_scalar(point.curve(), unsigned(reader)?, point.as_sec1_bytes())?
                    .into(),
            )
        }
        #[cfg(feature = "rsa")]
        KeyData::Rsa(public) => {
            let max = MAX_RSA_BITS / 8;
            let (d, p, q, coefficient) = (
                unsigned(reader)?,
                unsigned(reader)?,
                unsigned(reader)?,
                unsigned(reader)?,
            );
            if public.key_size() as usize > MAX_RSA_BITS
                || public.e().as_bytes().len() > 5
                || [d, p, q, coefficient].iter().any(|v| v.len() > max)
            {
                return Err(invalid("PPK RSA private key exceeds supported limits"));
            }
            let from = Mpint::from_positive_bytes;
            let private = RsaPrivateKey::new(from(d), from(coefficient), from(p), from(q))
                .map_err(encoding_error)?;
            let pair = RsaKeypair::new(public.clone(), private).map_err(encoding_error)?;
            let derived =
                rsa_private_key(&pair).map_err(|_| invalid("inconsistent PPK RSA keypair"))?;
            let inverse = Zeroizing::new(
                derived
                    .crt_coefficient()
                    .ok_or_else(|| invalid("missing PPK RSA CRT coefficient"))?,
            );
            if &**Zeroizing::new(inverse.to_be_bytes_trimmed_vartime()) != coefficient {
                return Err(invalid("inconsistent PPK RSA CRT coefficient"));
            }
            Ok(pair.into())
        }
        _ => Err(io::Error::new(
            ErrorKind::Unsupported,
            "unsupported PPK public key",
        )),
    }
}
