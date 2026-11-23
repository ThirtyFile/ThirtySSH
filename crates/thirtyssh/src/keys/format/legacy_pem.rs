use super::{PrivateKey, encoding_error, invalid, key_is_encrypted, pkcs};
use aes::{
    Aes128, Aes256,
    cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7},
};
use data_encoding::BASE64;
use md5::{Digest, Md5};
use std::io::{self, ErrorKind};
use zeroize::Zeroizing;

/// Legacy PEM cipher and initialization vector.
#[derive(Clone, Copy)]
enum LegacyCipher {
    Aes128Cbc([u8; 16]),
    Aes256Cbc([u8; 16]),
}

type Decoder = fn(&[u8]) -> io::Result<PrivateKey>;

pub(super) fn decode_legacy_pem(
    contents: &str,
    password: Option<&str>,
) -> Option<io::Result<PrivateKey>> {
    let mut lines = contents.lines();
    let (end, decode): (&str, Decoder) = match lines.next()? {
        "-----BEGIN RSA PRIVATE KEY-----" => ("-----END RSA PRIVATE KEY-----", pkcs::decode_pkcs1),
        "-----BEGIN EC PRIVATE KEY-----" => ("-----END EC PRIVATE KEY-----", pkcs::decode_sec1),
        _ => return None,
    };
    let proc_type = lines.next()?;
    if !proc_type.starts_with("Proc-Type:") && !proc_type.starts_with("DEK-Info:") {
        return None;
    }
    #[cfg(not(feature = "rsa"))]
    if end == "-----END RSA PRIVATE KEY-----" {
        return Some(Err(pkcs::rsa_pkcs1_unavailable()));
    }
    Some((|| {
        if proc_type != "Proc-Type: 4,ENCRYPTED" {
            return Err(invalid("invalid legacy PEM Proc-Type header"));
        }
        let (cipher, iv) = lines
            .next()
            .and_then(|line| line.strip_prefix("DEK-Info: "))
            .and_then(|line| line.split_once(','))
            .ok_or_else(|| invalid("invalid legacy PEM DEK-Info header"))?;
        let iv = decode_iv(iv)?;
        let encryption = match cipher {
            "AES-128-CBC" => LegacyCipher::Aes128Cbc(iv),
            "AES-256-CBC" => LegacyCipher::Aes256Cbc(iv),
            _ => {
                return Err(io::Error::new(
                    ErrorKind::Unsupported,
                    "unsupported legacy PEM cipher",
                ));
            }
        };
        if lines.next() != Some("") {
            return Err(invalid("missing legacy PEM header separator"));
        }
        let mut base64 = String::with_capacity(contents.len());
        for line in lines.by_ref() {
            if line == end {
                if lines.next().is_some() {
                    return Err(invalid("unexpected data after legacy PEM footer"));
                }
                let cipher = BASE64.decode(base64.as_bytes()).map_err(encoding_error)?;
                return decrypt(&cipher, password, encryption, decode);
            }
            base64.push_str(line);
        }
        Err(invalid("missing legacy PEM footer"))
    })())
}

fn decode_iv(hex: &str) -> io::Result<[u8; 16]> {
    let mut iv = [0; 16];
    if !hex.is_ascii() || hex.len() != 2 * iv.len() {
        return Err(invalid("invalid legacy PEM initialization vector"));
    }
    for (index, byte) in iv.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).map_err(encoding_error)?;
    }
    Ok(iv)
}

fn decrypt(
    bytes: &[u8],
    password: Option<&str>,
    encryption: LegacyCipher,
    decode: Decoder,
) -> io::Result<PrivateKey> {
    let password = password.ok_or_else(key_is_encrypted)?;
    let iv = match encryption {
        LegacyCipher::Aes128Cbc(iv) | LegacyCipher::Aes256Cbc(iv) => iv,
    };
    // OpenSSL legacy PEM uses EVP_BytesToKey with MD5, one iteration, and
    // the first eight IV bytes as salt. Only legacy import uses this KDF.
    let salt = &iv[..8];
    let first = Zeroizing::new(
        Md5::new()
            .chain_update(password)
            .chain_update(salt)
            .finalize(),
    );
    let mut plaintext = Zeroizing::new(bytes.to_vec());
    let unpadded = match encryption {
        LegacyCipher::Aes128Cbc(_) => cbc::Decryptor::<Aes128>::new(&first, (&iv).into())
            .decrypt_padded::<Pkcs7>(&mut plaintext),
        LegacyCipher::Aes256Cbc(_) => {
            let second = Zeroizing::new(
                Md5::new()
                    .chain_update(&first[..])
                    .chain_update(password)
                    .chain_update(salt)
                    .finalize(),
            );
            let mut key = Zeroizing::new([0u8; 32]);
            key[..16].copy_from_slice(&first);
            key[16..].copy_from_slice(&second);
            cbc::Decryptor::<Aes256>::new((&*key).into(), (&iv).into())
                .decrypt_padded::<Pkcs7>(&mut plaintext)
        }
    }
    .map_err(|_| decryption_failed())?;
    // CBC can yield valid padding with an incorrect passphrase. Treat
    // invalid decrypted key data the same as a padding failure.
    decode(unpadded).map_err(|error| {
        if error.kind() == ErrorKind::InvalidData {
            decryption_failed()
        } else {
            error
        }
    })
}

fn decryption_failed() -> io::Error {
    io::Error::new(
        ErrorKind::PermissionDenied,
        "could not decrypt legacy PEM key",
    )
}
