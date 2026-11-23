use super::{
    AgentIo, Client,
    protocol::{
        ADD_CONSTRAINED, ADD_IDENTITY, ADD_SMARTCARD, ADD_SMARTCARD_CONSTRAINED, CONSTRAIN_CONFIRM,
        CONSTRAIN_EXTENSION, CONSTRAIN_LIFETIME, EXTENSION, EXTENSION_FAILURE, EXTENSION_RESPONSE,
        FAILURE, LOCK, REMOVE_ALL, REMOVE_IDENTITY, REMOVE_SMARTCARD, SUCCESS, UNLOCK,
        check_frame_size, protocol,
    },
};
use crate::{
    SecretBuf,
    keys::{
        PrivateKey, PublicKey,
        agent::{Constraint, Error},
    },
    wire::Reader,
};
use ssh_encoding::Encode;
use std::str;
use zeroize::Zeroizing;

impl<S: AgentIo + Unpin> Client<S> {
    /// Hand a private key to the agent, to hold under the given constraints.
    pub async fn add(&mut self, key: &PrivateKey, constraints: &[Constraint]) -> Result<(), Error> {
        let comment = key.comment();
        let key = key.key_data();
        let len = 1usize
            .saturating_add(key.encoded_len()?)
            .saturating_add(comment.encoded_len()?)
            .saturating_add(constraints_size(constraints));
        check_frame_size(len)?;
        let mut packet = SecretBuf::with_capacity(len);
        packet.push(if constraints.is_empty() {
            ADD_IDENTITY
        } else {
            ADD_CONSTRAINED
        });
        key.encode(&mut packet)?;
        comment.encode(&mut packet)?;
        append_constraints(&mut packet, constraints)?;
        self.require_success(&packet).await
    }

    /// Make the agent forget one key.
    pub async fn remove(&mut self, key: &PublicKey) -> Result<(), Error> {
        self.require_success(&encode_fields(REMOVE_IDENTITY, &[&key.to_bytes()?], 0)?)
            .await
    }

    /// Make the agent forget every key.
    pub async fn remove_all(&mut self) -> Result<(), Error> {
        self.require_success(&[REMOVE_ALL]).await
    }

    /// Load the keys of a hardware token. `reader` names the token or its
    /// provider library in the agent's own terms.
    pub async fn add_token(
        &mut self,
        reader: &str,
        pin: &[u8],
        constraints: &[Constraint],
    ) -> Result<(), Error> {
        let code = if constraints.is_empty() {
            ADD_SMARTCARD
        } else {
            ADD_SMARTCARD_CONSTRAINED
        };
        let fields = [reader.as_bytes(), pin];
        let mut packet = encode_fields(code, &fields, constraints_size(constraints))?;
        append_constraints(&mut packet, constraints)?;
        self.require_success(&packet).await
    }

    /// Unload the keys of a hardware token.
    pub async fn remove_token(&mut self, reader: &str, pin: &[u8]) -> Result<(), Error> {
        self.require_success(&encode_fields(
            REMOVE_SMARTCARD,
            &[reader.as_bytes(), pin],
            0,
        )?)
        .await
    }

    /// Lock the agent until [`unlock`](Self::unlock) is given the same
    /// passphrase.
    pub async fn lock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.require_success(&encode_fields(LOCK, &[passphrase], 0)?)
            .await
    }

    pub async fn unlock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.require_success(&encode_fields(UNLOCK, &[passphrase], 0)?)
            .await
    }

    /// Send a named extension request with its encoded fields and return the
    /// payload of the reply, which is empty when the extension answers with
    /// a bare success. An agent without the extension is
    /// [`Error::ExtensionUnsupported`].
    pub async fn extension(&mut self, name: &[u8], data: &[u8]) -> Result<SecretBuf, Error> {
        let reply = self.send_extension(name, data).await?;
        let payload = match parse_extension(&reply, name)? {
            ExtensionReply::Unsupported => return Err(Error::ExtensionUnsupported),
            ExtensionReply::Success([]) => &[],
            ExtensionReply::Success(encoded) => {
                let mut reader = Reader::new(encoded);
                let payload = reader.string().map_err(protocol)?;
                reader.finish().map_err(protocol)?;
                payload
            }
            ExtensionReply::Data(payload) => payload,
        };
        Ok(SecretBuf::from(payload))
    }

    /// The extension names the agent reports, or `None` when it cannot be
    /// asked.
    pub async fn extensions(&mut self) -> Result<Option<Vec<String>>, Error> {
        const QUERY: &[u8] = b"query";
        let reply = self.send_extension(QUERY, &[]).await?;
        let payload = match parse_extension(&reply, QUERY)? {
            ExtensionReply::Unsupported => return Ok(None),
            ExtensionReply::Data(payload) | ExtensionReply::Success(payload) => payload,
        };
        let mut reader = Reader::new(payload);
        let mut names = Vec::new();
        while !reader.remaining().is_empty() {
            names.push(extension_name(reader.string().map_err(protocol)?)?.to_owned());
        }
        Ok(Some(names))
    }

    async fn send_extension(
        &mut self,
        name: &[u8],
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        extension_name(name)?;
        let mut packet = encode_fields(EXTENSION, &[name], data.len())?;
        packet.extend_from_slice(data);
        self.exchange(&packet).await
    }

    async fn require_success(&mut self, packet: &[u8]) -> Result<(), Error> {
        match self.exchange(packet).await?.as_slice() {
            [SUCCESS] => Ok(()),
            [FAILURE] => Err(Error::Refused),
            _ => Err(Error::Protocol),
        }
    }
}

fn string_size(field: &[u8]) -> usize {
    field.len().saturating_add(4)
}

fn encode_fields(code: u8, fields: &[&[u8]], suffix_len: usize) -> Result<SecretBuf, Error> {
    let len = fields
        .iter()
        .fold(1usize.saturating_add(suffix_len), |size, field| {
            size.saturating_add(string_size(field))
        });
    check_frame_size(len)?;
    let mut packet = SecretBuf::with_capacity(len);
    packet.push(code);
    for field in fields {
        field.encode(&mut packet)?;
    }
    Ok(packet)
}

fn constraints_size(constraints: &[Constraint]) -> usize {
    constraints.iter().fold(0usize, |size, constraint| {
        let length = match constraint {
            Constraint::Lifetime { .. } => 5,
            Constraint::ConfirmEachUse => 1,
            Constraint::Extension { name, data } => 1usize
                .saturating_add(string_size(name))
                .saturating_add(string_size(data)),
        };
        size.saturating_add(length)
    })
}

fn append_constraints(packet: &mut SecretBuf, constraints: &[Constraint]) -> Result<(), Error> {
    for constraint in constraints {
        match constraint {
            Constraint::Lifetime { seconds } => {
                packet.push(CONSTRAIN_LIFETIME);
                seconds.encode(packet)?;
            }
            Constraint::ConfirmEachUse => packet.push(CONSTRAIN_CONFIRM),
            Constraint::Extension { name, data } => {
                extension_name(name)?;
                packet.push(CONSTRAIN_EXTENSION);
                name.encode(packet)?;
                data.encode(packet)?;
            }
        }
    }
    Ok(())
}

enum ExtensionReply<'a> {
    Unsupported,
    Success(&'a [u8]),
    Data(&'a [u8]),
}

fn parse_extension<'a>(reply: &'a [u8], name: &[u8]) -> Result<ExtensionReply<'a>, Error> {
    match reply {
        [FAILURE] => Ok(ExtensionReply::Unsupported),
        [EXTENSION_FAILURE] => Err(Error::ExtensionFailed),
        [SUCCESS, payload @ ..] => Ok(ExtensionReply::Success(payload)),
        [EXTENSION_RESPONSE, payload @ ..] => {
            let mut reader = Reader::new(payload);
            if reader.string().map_err(protocol)? != name {
                return Err(Error::Protocol);
            }
            Ok(ExtensionReply::Data(reader.remaining()))
        }
        _ => Err(Error::Protocol),
    }
}

fn extension_name(field: &[u8]) -> Result<&str, Error> {
    let name = str::from_utf8(field).map_err(protocol)?;
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(Error::Protocol);
    }
    Ok(name)
}
