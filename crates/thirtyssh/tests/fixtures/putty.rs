//! PuTTYgen 0.83 generated these encrypted fixtures from one disposable key.
pub const PASSPHRASE: &str = "puttygen-fixture-passphrase";
pub const FINGERPRINT: &str = "SHA256:nRnz5JE8Pa6U3OFtstqkSdIlPljrrjrgbRrYiLB1lcc";

pub fn encrypted_vectors() -> [String; 2] {
    let public = concat!(
        "Encryption: aes256-cbc\nComment: thirtyssh-disposable-ppk-test\nPublic-Lines: 2\n",
        "AAAAC3NzaC1lZDI1NTE5AAAAII7ARJwq/8ouFrIdOkmrMMcUOtob1iwkiAjd944v\n4k9W\n",
    );
    let kdf = concat!(
        "Key-Derivation: Argon2id\nArgon2-Memory: 64\nArgon2-Passes: 2\nArgon2-Parallelism: 2\n",
        "Argon2-Salt: 8855e973fa9671153c45352752e6c23e\n",
    );
    let v2 = concat!(
        "Private-Lines: 1\ndEKfsocIuVPp09/pl9/eqgBaFXkwQ5W9DEYJgBijUe2nOoT6p4eD1Bt45ebG64x2\n",
        "Private-MAC: 2ab0d7044d6ef37d0b3b39d0737a892e65fb2ed7\n",
    );
    let v3 = concat!(
        "Private-Lines: 1\noFU1zSSHNI7rrfyVhhSiHmVui9wzG0pgAv5c5JrcBFQhJ+pyRWAFm+IDp6+Qzfbc\n",
        "Private-MAC: 0130df8801b8965c13272419dfe3a191338eadaaace96a5b69c47267925a2edc\n",
    );
    [
        format!("PuTTY-User-Key-File-2: ssh-ed25519\n{public}{v2}"),
        format!("PuTTY-User-Key-File-3: ssh-ed25519\n{public}{kdf}{v3}"),
    ]
}
