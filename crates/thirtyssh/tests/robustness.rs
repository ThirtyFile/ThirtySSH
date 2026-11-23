//! Decoders fed arbitrary and damaged input. Nothing here checks what a
//! decoder returns, only that it returns: a panic, an overflow or an
//! unbounded allocation on input a peer or a file controls is the failure.
use thirtyssh::{
    clear_packet,
    forward::{TcpipForward, TcpipOpen, X11Open},
    keys::{
        Algorithm, Certificate, PrivateKey, PrivateKeyReader, PublicKey, ssh_key::LineEnding,
        system_rng,
    },
    known_hosts::KnownHosts,
    pty,
    session::Request,
    wire::Reader,
};

/// A fixed-seed generator, so a failure reproduces.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let length = self.below(max + 1);
        (0..length).map(|_| self.next() as u8).collect()
    }

    /// Change a few bytes of `valid`, or cut it short.
    fn damage(&mut self, valid: &[u8]) -> Vec<u8> {
        let mut bytes = valid.to_vec();
        for _ in 0..=self.below(4) {
            let at = self.below(bytes.len());
            bytes[at] = self.next() as u8;
        }
        if self.below(4) == 0 {
            bytes.truncate(self.below(bytes.len()));
        }
        bytes
    }
}

const REQUESTS: &[&[u8]] = &[
    b"pty-req",
    b"env",
    b"exec",
    b"subsystem",
    b"window-change",
    b"signal",
    b"exit-status",
    b"exit-signal",
    b"x11-req",
    b"xon-xoff",
    b"auth-agent-req@openssh.com",
    b"unknown@example.test",
];

#[tokio::test]
async fn wire_decoders_return_on_arbitrary_bytes() {
    let mut random = Xorshift(0x9e37_79b9_7f4a_7c15);
    for _ in 0..20_000 {
        let bytes = random.bytes(96);
        let name = REQUESTS[random.below(REQUESTS.len())];
        let _ = Request::decode(name, &bytes);
        let _ = pty::decode_modes(&bytes);
        for kind in [b"direct-tcpip".as_slice(), b"forwarded-tcpip"] {
            let _ = TcpipOpen::decode(kind, &bytes);
        }
        for name in [b"tcpip-forward".as_slice(), b"cancel-tcpip-forward"] {
            let _ = TcpipForward::decode(name, &bytes);
        }
        let _ = X11Open::decode(b"x11", &bytes);
        let _ = PublicKey::from_bytes(&bytes);
        let _ = Certificate::from_bytes(&bytes);

        let mut reader = Reader::new(&bytes);
        let _ = reader.uint32();
        let _ = reader.string();
        let _ = reader.name_list();
        let _ = reader.boolean();
        let _ = reader.finish();

        // A length field decides how much a packet reader asks for.
        let _ = clear_packet::read(&mut bytes.as_slice()).await;
    }
}

#[test]
fn key_readers_return_on_damaged_keys() {
    let mut random = Xorshift(0x2545_f491_4f6c_dd1d);
    let reader = PrivateKeyReader::new();
    for algorithm in [
        Algorithm::Ed25519,
        Algorithm::Ecdsa {
            curve: thirtyssh::keys::EcdsaCurve::NistP256,
        },
    ] {
        let key = PrivateKey::random(&mut system_rng(), algorithm).unwrap();
        let text = key.to_openssh(LineEnding::LF).unwrap();
        let public = key.public_key().to_bytes().unwrap();
        for _ in 0..2_000 {
            let damaged = random.damage(text.as_bytes());
            let _ = reader.text(&String::from_utf8_lossy(&damaged));
            let _ = reader.der(&damaged);
            let _ = PublicKey::from_bytes(&random.damage(&public));
        }
    }
    for _ in 0..2_000 {
        let _ = reader.der(&random.bytes(256));
    }
}

#[test]
fn known_hosts_lookups_return_on_damaged_files() {
    let mut random = Xorshift(0xd6e8_feb8_6659_fd93);
    let key = PrivateKey::random(&mut system_rng(), Algorithm::Ed25519).unwrap();
    let line = key.public_key().to_openssh().unwrap();
    let valid = format!(
        "host.test {line}\n@cert-authority *.test {line}\n@revoked other.test {line}\n\
         |1|AAAAAAAAAAAAAAAAAAAAAAAAAAA=|AAAAAAAAAAAAAAAAAAAAAAAAAAA= {line}\n"
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("known_hosts");
    let host = key.public_key();
    for _ in 0..500 {
        std::fs::write(&path, random.damage(valid.as_bytes())).unwrap();
        let mut hosts = KnownHosts::new();
        if hosts.load(&path).is_ok() {
            let _ = hosts.check_public_key("host.test", 22, host);
            let _ = hosts.check_public_key("other.test", 2222, host);
        }
    }
}
