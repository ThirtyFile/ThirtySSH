use super::{AuthDecision, Banner, Outcome, malformed};
use crate::{clear_packet::invalid, kex, wire::Reader};
use std::{io, str};
use zeroize::Zeroizing;

pub(super) const NAME: &[u8] = b"keyboard-interactive";
pub(super) const INFO_REQUEST: u8 = 60;
pub(super) const INFO_RESPONSE: u8 = 61;
const MAX_PAYLOAD: usize = 32_768;
pub(super) const MAX_ROUNDS: usize = 64;

#[derive(Debug, Eq, PartialEq)]
pub struct Prompt {
    pub prompt: String,
    pub echo: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Challenge {
    pub name: String,
    pub instructions: String,
    pub language: String,
    pub prompts: Vec<Prompt>,
}

/// Either a request for a new round of answers or a final factor decision.
#[derive(Debug, Eq, PartialEq)]
pub enum InteractiveDecision {
    Challenge(Challenge),
    Finished(AuthDecision),
}

#[derive(Debug, Eq, PartialEq)]
pub enum InteractiveResponse {
    Challenge(Challenge),
    Finished(Outcome),
}

#[derive(Debug, Eq, PartialEq)]
pub struct InteractiveAttempt {
    pub response: InteractiveResponse,
    pub banners: Vec<Banner>,
}

fn field<'a>(reader: &mut Reader<'a>) -> io::Result<&'a str> {
    str::from_utf8(reader.string().map_err(malformed)?)
        .map_err(|_| invalid("invalid UTF-8 in SSH keyboard-interactive field"))
}

fn check_size(size: usize) -> io::Result<()> {
    if size > MAX_PAYLOAD {
        return Err(invalid("SSH keyboard-interactive packet exceeds limit"));
    }
    Ok(())
}

pub(super) fn request_fields(submethods: &str) -> io::Result<Vec<u8>> {
    check_size(8 + submethods.len())?;
    kex::fields(None, &[b"", submethods.as_bytes()])
}

pub(super) fn read_initial(mut reader: Reader<'_>) -> io::Result<&str> {
    check_size(reader.remaining().len())?;
    field(&mut reader)?;
    let submethods = field(&mut reader)?;
    reader.finish().map_err(malformed)?;
    Ok(submethods)
}

impl Challenge {
    pub(super) fn encode(&self) -> io::Result<Vec<u8>> {
        let size = self.prompts.iter().fold(
            17 + self.name.len() + self.instructions.len() + self.language.len(),
            |size, prompt| size.saturating_add(5 + prompt.prompt.len()),
        );
        check_size(size)?;
        let mut packet = kex::fields(
            Some(INFO_REQUEST),
            &[
                self.name.as_bytes(),
                self.instructions.as_bytes(),
                self.language.as_bytes(),
            ],
        )?;
        packet.extend_from_slice(&(self.prompts.len() as u32).to_be_bytes());
        for prompt in &self.prompts {
            packet.extend_from_slice(&(prompt.prompt.len() as u32).to_be_bytes());
            packet.extend_from_slice(prompt.prompt.as_bytes());
            packet.push(u8::from(prompt.echo));
        }
        Ok(packet)
    }

    pub(super) fn decode(packet: &[u8]) -> io::Result<Self> {
        check_size(packet.len())?;
        let mut reader = Reader::new(&packet[1..]);
        let name = field(&mut reader)?.to_owned();
        let instructions = field(&mut reader)?.to_owned();
        let language = field(&mut reader)?.to_owned();
        let count = reader.uint32().map_err(malformed)? as usize;
        if count > reader.remaining().len() / 5 {
            return Err(invalid("invalid SSH keyboard-interactive prompt count"));
        }
        let mut prompts = Vec::with_capacity(count);
        for _ in 0..count {
            prompts.push(Prompt {
                prompt: field(&mut reader)?.to_owned(),
                echo: reader.boolean().map_err(malformed)?,
            });
        }
        reader.finish().map_err(malformed)?;
        Ok(Self {
            name,
            instructions,
            language,
            prompts,
        })
    }
}

pub(super) fn encode_answers(answers: &[String]) -> io::Result<Zeroizing<Vec<u8>>> {
    let size = answers
        .iter()
        .fold(5usize, |size, answer| size.saturating_add(4 + answer.len()));
    check_size(size)?;
    let mut packet = Zeroizing::new(Vec::with_capacity(size));
    packet.push(INFO_RESPONSE);
    packet.extend_from_slice(&(answers.len() as u32).to_be_bytes());
    for answer in answers {
        packet.extend_from_slice(&(answer.len() as u32).to_be_bytes());
        packet.extend_from_slice(answer.as_bytes());
    }
    Ok(packet)
}

pub(super) fn decode_answers(packet: &[u8], expected: usize) -> io::Result<Option<Vec<&[u8]>>> {
    check_size(packet.len())?;
    let mut reader = Reader::new(&packet[1..]);
    let count = reader.uint32().map_err(malformed)? as usize;
    if count != expected {
        return Ok(None);
    }
    if count > reader.remaining().len() / 4 {
        return Err(invalid("invalid SSH keyboard-interactive response count"));
    }
    let mut answers = Vec::with_capacity(count);
    for _ in 0..count {
        answers.push(field(&mut reader)?.as_bytes());
    }
    reader.finish().map_err(malformed)?;
    Ok(Some(answers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_prompt_count_and_oversized_challenges_are_rejected() {
        let mut challenge = Challenge {
            name: "fixture".into(),
            instructions: "message".into(),
            language: "en".into(),
            prompts: Vec::new(),
        };
        let mut packet = challenge.encode().unwrap();
        let count = packet.len() - 4;
        packet[count..].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Challenge::decode(&packet).is_err());
        challenge.instructions = "x".repeat(MAX_PAYLOAD);
        assert!(challenge.encode().is_err());
        assert!(Challenge::decode(&vec![INFO_REQUEST; MAX_PAYLOAD + 1]).is_err());
    }

    #[test]
    fn responses_check_length_encoding_and_the_packet_budget() {
        assert!(
            decode_answers(&[INFO_RESPONSE, 0, 0, 0, 1], 0)
                .unwrap()
                .is_none()
        );
        assert!(decode_answers(&[INFO_RESPONSE, 0, 0, 0, 1], 1).is_err());
        assert!(decode_answers(&[INFO_RESPONSE, 0, 0, 0, 1, 0, 0, 0, 1, 0xff], 1).is_err());
        assert!(encode_answers(&["x".repeat(MAX_PAYLOAD)]).is_err());
        let answers = [String::new(), "祕密".into()];
        let packet = encode_answers(&answers).unwrap();
        assert_eq!(
            decode_answers(&packet, 2).unwrap().unwrap(),
            [b"", "祕密".as_bytes()]
        );
    }
}
