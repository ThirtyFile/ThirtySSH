//! Negotiated packet protection algorithms.

pub use crate::kex::gex::GexSizes;

/// Implemented key exchanges and the capability markers for initial KEXINIT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kex {
    MlKem768X25519Sha256,
    Curve25519,
    Curve25519Libssh,
    EcdhNistP256,
    EcdhNistP384,
    EcdhNistP521,
    DhGroup1Sha1,
    DhGroup14Sha1,
    DhGroup14Sha256,
    DhGroup15Sha512,
    DhGroup16Sha512,
    DhGroup17Sha512,
    DhGroup18Sha512,
    DhGexSha1,
    DhGexSha256,
    /// Nonstandard mode without a host proof or session keys. Requires
    /// this to be the only method and both directions to use clear framing.
    None,
    ExtInfoClient,
    ExtInfoServer,
    StrictClient,
    StrictServer,
}

impl Kex {
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlKem768X25519Sha256 => "mlkem768x25519-sha256",
            Self::Curve25519 => "curve25519-sha256",
            Self::Curve25519Libssh => "curve25519-sha256@libssh.org",
            Self::EcdhNistP256 => "ecdh-sha2-nistp256",
            Self::EcdhNistP384 => "ecdh-sha2-nistp384",
            Self::EcdhNistP521 => "ecdh-sha2-nistp521",
            Self::DhGroup1Sha1 => "diffie-hellman-group1-sha1",
            Self::DhGroup14Sha1 => "diffie-hellman-group14-sha1",
            Self::DhGroup14Sha256 => "diffie-hellman-group14-sha256",
            Self::DhGroup15Sha512 => "diffie-hellman-group15-sha512",
            Self::DhGroup16Sha512 => "diffie-hellman-group16-sha512",
            Self::DhGroup17Sha512 => "diffie-hellman-group17-sha512",
            Self::DhGroup18Sha512 => "diffie-hellman-group18-sha512",
            Self::DhGexSha1 => "diffie-hellman-group-exchange-sha1",
            Self::DhGexSha256 => "diffie-hellman-group-exchange-sha256",
            Self::None => "none",
            Self::ExtInfoClient => "ext-info-c",
            Self::ExtInfoServer => "ext-info-s",
            Self::StrictClient => "kex-strict-c-v00@openssh.com",
            Self::StrictServer => "kex-strict-s-v00@openssh.com",
        }
    }

    pub(crate) const fn is_method(self) -> bool {
        self.digest().is_some()
    }

    /// The hash a method uses for its exchange hash and key derivation.
    /// The names that only signal a capability have none. Every variant is
    /// listed, so a new method cannot be added without choosing its hash.
    pub(crate) const fn digest(self) -> Option<KexDigest> {
        Some(match self {
            Self::DhGroup1Sha1 | Self::DhGroup14Sha1 | Self::DhGexSha1 => KexDigest::Sha1,
            Self::MlKem768X25519Sha256
            | Self::Curve25519
            | Self::Curve25519Libssh
            | Self::EcdhNistP256
            | Self::DhGroup14Sha256
            | Self::DhGexSha256
            | Self::None => KexDigest::Sha256,
            Self::EcdhNistP384 => KexDigest::Sha384,
            Self::EcdhNistP521
            | Self::DhGroup15Sha512
            | Self::DhGroup16Sha512
            | Self::DhGroup17Sha512
            | Self::DhGroup18Sha512 => KexDigest::Sha512,
            Self::ExtInfoClient | Self::ExtInfoServer | Self::StrictClient | Self::StrictServer => {
                return None;
            }
        })
    }

    /// The key exchange method with this wire name.
    pub(crate) fn method(name: &str) -> Option<Self> {
        const METHODS: [Kex; 16] = [
            Kex::MlKem768X25519Sha256,
            Kex::Curve25519,
            Kex::Curve25519Libssh,
            Kex::EcdhNistP256,
            Kex::EcdhNistP384,
            Kex::EcdhNistP521,
            Kex::DhGroup1Sha1,
            Kex::DhGroup14Sha1,
            Kex::DhGroup14Sha256,
            Kex::DhGroup15Sha512,
            Kex::DhGroup16Sha512,
            Kex::DhGroup17Sha512,
            Kex::DhGroup18Sha512,
            Kex::DhGexSha1,
            Kex::DhGexSha256,
            Kex::None,
        ];
        METHODS.into_iter().find(|method| method.name() == name)
    }
}

/// The hash function of a key exchange method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KexDigest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cipher {
    ChaCha20Poly1305,
    Aes256Gcm,
    Aes128Gcm,
    Aes256Ctr,
    Aes192Ctr,
    Aes128Ctr,
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    #[cfg(feature = "des")]
    TripleDesCbc,
    /// Unencrypted and unauthenticated packet framing.
    Clear,
    /// Alternate wire name for the same unprotected framing as `Clear`.
    None,
}

impl Cipher {
    pub(crate) const PREFERENCE: [Self; 6] = [
        Self::ChaCha20Poly1305,
        Self::Aes256Gcm,
        Self::Aes128Gcm,
        Self::Aes256Ctr,
        Self::Aes192Ctr,
        Self::Aes128Ctr,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20-poly1305@openssh.com",
            Self::Aes128Gcm => "aes128-gcm@openssh.com",
            Self::Aes256Gcm => "aes256-gcm@openssh.com",
            Self::Aes128Ctr => "aes128-ctr",
            Self::Aes192Ctr => "aes192-ctr",
            Self::Aes256Ctr => "aes256-ctr",
            Self::Aes128Cbc => "aes128-cbc",
            Self::Aes192Cbc => "aes192-cbc",
            Self::Aes256Cbc => "aes256-cbc",
            #[cfg(feature = "des")]
            Self::TripleDesCbc => "3des-cbc",
            Self::Clear => "clear",
            Self::None => "none",
        }
    }

    pub(crate) const fn block_size(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 | Self::Clear | Self::None => 8,
            #[cfg(feature = "des")]
            Self::TripleDesCbc => 8,
            _ => 16,
        }
    }

    pub const fn is_aead(self) -> bool {
        matches!(
            self,
            Self::ChaCha20Poly1305 | Self::Aes128Gcm | Self::Aes256Gcm
        )
    }

    pub(crate) const fn needs_mac(self) -> bool {
        !self.is_aead() && !self.is_unprotected()
    }

    pub(crate) const fn is_unprotected(self) -> bool {
        matches!(self, Self::Clear | Self::None)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mac {
    HmacSha256Etm,
    HmacSha512Etm,
    HmacSha256,
    HmacSha512,
    HmacSha1,
    HmacSha1Etm,
    /// Advertise the absence of a separate MAC. Invalid with CTR and CBC.
    None,
}

impl Mac {
    pub(crate) const PREFERENCE: [Self; 4] = [
        Self::HmacSha256Etm,
        Self::HmacSha512Etm,
        Self::HmacSha256,
        Self::HmacSha512,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha2-256",
            Self::HmacSha512 => "hmac-sha2-512",
            Self::HmacSha256Etm => "hmac-sha2-256-etm@openssh.com",
            Self::HmacSha512Etm => "hmac-sha2-512-etm@openssh.com",
            Self::HmacSha1 => "hmac-sha1",
            Self::HmacSha1Etm => "hmac-sha1-etm@openssh.com",
            Self::None => "none",
        }
    }

    pub const fn is_etm(self) -> bool {
        matches!(
            self,
            Self::HmacSha256Etm | Self::HmacSha512Etm | Self::HmacSha1Etm
        )
    }

    pub(crate) const fn tag_len(self) -> usize {
        match self {
            Self::HmacSha256 | Self::HmacSha256Etm => 32,
            Self::HmacSha512 | Self::HmacSha512Etm => 64,
            Self::HmacSha1 | Self::HmacSha1Etm => 20,
            Self::None => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Suite {
    pub cipher: Cipher,
    /// `None` for AEAD and unprotected ciphers. CTR and CBC require a HMAC.
    pub mac: Option<Mac>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketAlgorithms {
    pub client_to_server: Suite,
    pub server_to_client: Suite,
}

/// Ordered algorithm lists for one direction of the SSH connection.
#[derive(Clone, Debug)]
pub struct DirectionPreferences {
    pub ciphers: Vec<Cipher>,
    pub macs: Vec<Mac>,
}

impl Default for DirectionPreferences {
    fn default() -> Self {
        Self {
            ciphers: Cipher::PREFERENCE.to_vec(),
            macs: Mac::PREFERENCE.to_vec(),
        }
    }
}

/// Supported and preferred protection algorithms for a transport.
/// The same lists are used during the initial handshake and rekey.
#[derive(Clone, Debug, Default)]
pub struct PacketPreferences {
    pub client_to_server: DirectionPreferences,
    pub server_to_client: DirectionPreferences,
}

/// SSH payload compression. Both zlib modes require the `flate2` feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Compression {
    None,
    Zlib,
    DelayedZlib,
}

impl Compression {
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zlib => "zlib",
            Self::DelayedZlib => "zlib@openssh.com",
        }
    }

    pub(crate) const fn available(self) -> bool {
        matches!(self, Self::None) || cfg!(feature = "flate2")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompressionAlgorithms {
    pub client_to_server: Compression,
    pub server_to_client: Compression,
}

/// Ordered compression lists. Defaults to uncompressed traffic.
#[derive(Clone, Debug)]
pub struct CompressionPreferences {
    pub client_to_server: Vec<Compression>,
    pub server_to_client: Vec<Compression>,
}

impl Default for CompressionPreferences {
    fn default() -> Self {
        Self {
            client_to_server: vec![Compression::None],
            server_to_client: vec![Compression::None],
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransportPreferences {
    /// Ordered methods and optional role-specific markers.
    ///
    /// # Security
    ///
    /// Keep [`Kex::StrictClient`] and [`Kex::StrictServer`] in this list.
    /// They enable strict key exchange, the mitigation for the Terrapin
    /// prefix-truncation attack (CVE-2023-48795). A custom list that omits the
    /// marker for the local role silently turns the mitigation off.
    pub kex: Vec<Kex>,
    pub packet: PacketPreferences,
    pub compression: CompressionPreferences,
    /// Client bounds for Diffie–Hellman group exchange.
    pub gex: GexSizes,
}

impl Default for TransportPreferences {
    fn default() -> Self {
        Self {
            kex: vec![
                Kex::MlKem768X25519Sha256,
                Kex::Curve25519,
                Kex::Curve25519Libssh,
                Kex::EcdhNistP256,
                Kex::EcdhNistP384,
                Kex::EcdhNistP521,
                Kex::DhGexSha256,
                Kex::DhGroup18Sha512,
                Kex::DhGroup17Sha512,
                Kex::DhGroup16Sha512,
                Kex::DhGroup15Sha512,
                Kex::DhGroup14Sha256,
                Kex::StrictClient,
                Kex::StrictServer,
                Kex::ExtInfoClient,
                Kex::ExtInfoServer,
            ],
            packet: PacketPreferences::default(),
            compression: CompressionPreferences::default(),
            gex: GexSizes::default(),
        }
    }
}
