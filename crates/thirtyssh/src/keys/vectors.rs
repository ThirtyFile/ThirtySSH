use super::{Algorithm, decode_public_key, verify};
use data_encoding::BASE64;
use std::io::ErrorKind;

// OpenSSL 3.5.5 produced these independent signatures with openssl dgst.
// The public blobs were exported by OpenSSH ssh-keygen. The ECDSA DER
// integers were wrapped as SSH mpints, and the private keys were discarded.
const MESSAGE: &[u8] = b"ThirtySSH independent signature vector\n";
#[cfg(feature = "rsa")]
const RSA_PUBLIC: &str = concat!(
    "AAAAB3NzaC1yc2EAAAADAQABAAABAQDZUZBCkb8Rn1b8h7WpDerL9Pfu3aPcc3Vkcm556kir",
    "C21yUozgKfveLBE1qW5RB0qUKpYedFkdug1gZCgb4SK14zcOddAQlpgxWcEMGerVOEcpiTPP",
    "H+8jZTFjZ9WWyDo0JUA/tjhrsvkuSBqeN+gwStsZZvpeHW0VPK/XGqbKNOTpwF832ybYYh8q",
    "vGF0c7EWZ9LCDFAEMmAAA+NaH3R0wpoNbyZDpk2SRPJO5KdkPXhcnVgLPluaJV1n3dcO5Jhw",
    "nxRR+vjo4DlUzDjCu9l05RKAkm5JGdvYz5mJZDC8ASAX97hNjgib8RcY9yNjNn7ttWXYSPF6",
    "ozKZXzYYUqI7",
);

struct Vector {
    algorithm: &'static str,
    public: &'static str,
    proof: &'static str,
}

const VECTORS: &[Vector] = &[
    #[cfg(feature = "dsa")]
    Vector {
        // OpenSSL via Python cryptography using 1024-bit DSA, a SHA-1
        // digest, and a leading zero octet in the 20-byte r field.
        algorithm: "ssh-dss",
        public: concat!(
            "AAAAB3NzaC1kc3MAAACBANFsDGUENDhO0yghlZL2NntFxGi7nt8Tbba5wA0CurvZ5jXZTmAM",
            "ouzMdiMg9SZ8uNFfsM+F/X+cb3shTPzybmaGG9eGqFqzY/2gDZvBbLA3xGBQMBDzKyvH0Khd",
            "LIc6fEAwg1PLuVJ7lKt6toXuld9FqG/8SVU4WwDTOzu95UoFAAAAFQDl9nOGQOIkIenIKls9",
            "xGTmuXp3qQAAAIEAt9Y9PbhAa3xzHuTI7RM+rWx5+dS/+4QQLbn/aj3NiRhaNIL0ZNUKvtrP",
            "Oy0FEzDOXktw8WeccL694fN2NKV5l3nkNM5DvYnj6KWQ3Kgc/d3KXi5JO/gIxHllePgFrtlB",
            "U2Vh5RE461TU9I5eGwIHB5M264fetrg3Uu3HkCj7B7gAAACBAJzJibRzUaI+JEhNkWcepIPO",
            "HifwOa0sKbmfMINRYR8ER83s7U1fW7F8HlBhUu6U7RoERewPWLpqK7LiShhIoRb9tMxRt38k",
            "/+oWgZo8BdS2T/gqqqslWJoEAG3gnejsS2K0Y9/0xR/JP4UqJsLUW/geB08WcujzLCPhyauv",
            "sud9",
        ),
        proof: concat!(
            "AAAAB3NzaC1kc3MAAAAoAAxCCajkTd4ESR4QRc23q6g4awFq8DvRKJnOqHoGphpjd0qi6DNZ",
            "nA==",
        ),
    },
    #[cfg(feature = "rsa")]
    Vector {
        // OpenSSL via Python cryptography 46.0.7 using PKCS#1 v1.5 and SHA-1.
        algorithm: "ssh-rsa",
        public: concat!(
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQCiDlAMenLEQcyUM6u45HMKNlS0YW7TeFvEGcEKpj9E",
            "MRygfjto3auhqxS+NCEA6s0XeDv0skLAcvYDcw1sP8m1qz4utalxeWEvGy0nlK0ZCt9u6bvx",
            "Fe7WscbMjlH/9DWv2GKcCYR7Od74fO/hs1njp0Kc5nJgTKRjWYaAPzbZsTWmxqn4LD4m7Gjq",
            "IGOTmJJ3f4TuPyhcqh94ICxrD1NKKRKhP66POmntN5955ABJRBqmuuxp/5TpKxBDB+cjn2ds",
            "2+jbo/MP0Sh4ZxXTH3LR51bhazQLh8MJQwxtA1Nv7NeGPfvopT3Jk5Es447gnQConrKuSXiO",
            "AX/qb6TeAPkr",
        ),
        proof: concat!(
            "AAAAB3NzaC1yc2EAAAEAPNRLUeuh9/hU99H2WkwRHfMfXXPhjyTU7ESlzpVKB2v6XVcsCYMj",
            "Rb+660UR0322s+G+IulFMeY0Kzs1/eFuDPa/5zgYISyLAHtt3iFlbW39TrhN4QSY/6JlDSeJ",
            "QgPgnbdhV2NJ705T9L5NMA3EKi8jaTAGkZ8tOVsdHpNI4uS9qRvmm2SGV6bMYCzaF5HvxkUt",
            "FuD3oRvYrS+2NuoSj45F4knuL6IgBT2bPZjgOiJYFkIqFBSYCTaxhkFDZEiuRaS9vrwjYzNb",
            "pIgoq2OV2R0HTNzhuxVTMRB+z+r/5sRWXQfgbunQMM3vB6hjKP1yBi26LOBetYwMwQM1EEDl",
            "/Q==",
        ),
    },
    #[cfg(feature = "rsa")]
    Vector {
        algorithm: "rsa-sha2-256",
        public: RSA_PUBLIC,
        proof: concat!(
            "AAAADHJzYS1zaGEyLTI1NgAAAQAp5tXidKPzsrfEcMA6rLbLbcvNDisuNysWRFcX265r2ej+",
            "Iwqbr9JqcUj8QIvH2nKIJmdU5ym1qzs/E1wryJvkDo4ya8M2F+nI/YMxuw+SGhKt1UcjoWgw",
            "gqn4qNAJIbspwyZyybwaSZFFCwktVfo+3uP4lxq0Lkv/niIHwK6qH6JBTmTl5iE89Qqtc0/b",
            "i32kU3YwLk4v3XyBokgkmd25Z1qa9ySQhXlxkTWkm/0sFsBAIlafeYfNINXANvr2NSexbbmy",
            "HXO4O3r1kgGmmLkaEsjbMHh0qsZVGQO0PmzDuvURIa+XoOzsAh1mDGlBZ4wrWDAZUYQNHxF4",
            "ENr3eru7",
        ),
    },
    #[cfg(feature = "rsa")]
    Vector {
        algorithm: "rsa-sha2-512",
        public: RSA_PUBLIC,
        proof: concat!(
            "AAAADHJzYS1zaGEyLTUxMgAAAQAMoE2pP7UPEZw86hwcQctFwHV2cgy5f3vUsnscS8X4BY+d",
            "0dYl7VKAiTpx1yuZLXIoKqZNS1lE0P3pyo0J+W6Iq4kHlAstnPhdN7j9gXQeZDaauwn+Ewmp",
            "tPtde9FKjSh2peqrHRZK0ctT23f7Rwu4kxNxI4szmau13PuSjtMxeWOUJiETlyvbPCEwR9sC",
            "wgqKzF4NQd2HtmdgHDK4A1MHgsGfdtQHtV9Y5QpZqMgiZDs1KsKFHBaHKauN0K8Jr9MviCj7",
            "C8OICSjH4WkFPArE5oHh6/PBk8DONvmA9tCcpRDujdBSoniMMREydcwc4d+fCkBv+KIPAPQf",
            "A063o/SZ",
        ),
    },
    Vector {
        algorithm: "ecdsa-sha2-nistp256",
        public: concat!(
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFRyN0LEs3uSFhY5pVVP",
            "KKfVwOuSPZcSn5XbTH9XYH22aVxBzF1ddvm042V2dQqJ7VazIOmjfPChuUFcYUS5OHE=",
        ),
        proof: concat!(
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABKAAAAIQC1AWaVyVtAggTaIHQD/+c0ik4GPZ+r",
            "IkG5+C/YqYHJhQAAACEAiImY2yrlVhvFIceDizZOK2qLfmCsarV7wtqNq3mtYuU=",
        ),
    },
    Vector {
        algorithm: "ecdsa-sha2-nistp384",
        public: concat!(
            "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBGRv13QuT2vIMcPKDQdt",
            "St6pDkpgOZQLcuFE4yhW6i+McqwQcR4ZOxH27iRQ2nwTO7sN31i0YFuV0VrMNVVd2A/OpUC/",
            "2WFua6b81OJ5ddcaz9ZLNOKfgJ52v3uWeFsMgQ==",
        ),
        proof: concat!(
            "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAABqAAAAMQCI84WVFHqD8L9CgnFGpu//EGZQtUHk",
            "aIeZfSfM5lS50l6lUp8lSyZJJD3wdccoBdoAAAAxAKaMIXDAuPx1vpvaUyYnUDM6Tbt1OHq+",
            "09TyzwVwaT3/Tg3DjHhF3m2K1gCOdVO3LQ==",
        ),
    },
    Vector {
        algorithm: "ecdsa-sha2-nistp521",
        public: concat!(
            "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHwy368GK1XiDc/b/OU",
            "2ftqUfm7pl5Vo0H5jP9IZGYMCBwOpp83W3XpeUv8KulmXr7s03V9082AhiGHo8fZNWCEJQCh",
            "N/526jse0+XqfIao2kKWLatNI6Y4gaznSLLiETUU5bihgt4MELs1yIsB30w/5BPjiDFaMLpM",
            "ygvyAIWGQP2LTQ==",
        ),
        proof: concat!(
            "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAACLAAAAQgDbIONGV5TPd5pWr6y73AM9rUX14Lbe",
            "28DEK9pZ0rzYu6sq9pHQD1AWNtcCVFFFL0hGXAaE3M7j3rI+guC5vVv5BgAAAEE7VGhmGHpd",
            "xuAll0xq+cQXBh4YKUjuPbSsLkk8YQFn4BsCMwW3WkW62jQ1hH/gBv469oaPK3+v4nEBa1W2",
            "6sYXDA==",
        ),
    },
];

#[test]
fn verify_independent_signature_vectors_with_exact_wire_framing() {
    for vector in VECTORS {
        let algorithm = Algorithm::new(vector.algorithm).unwrap();
        let public = BASE64.decode(vector.public.as_bytes()).unwrap();
        let key = decode_public_key(&algorithm, &public).unwrap();
        assert_eq!(key.to_bytes().unwrap(), public);

        let mut proof = BASE64.decode(vector.proof.as_bytes()).unwrap();
        assert!(
            verify(key.key_data(), &algorithm, MESSAGE, &proof).unwrap(),
            "{}",
            vector.algorithm
        );
        assert!(
            !verify(key.key_data(), &algorithm, b"different message", &proof).unwrap(),
            "{}",
            vector.algorithm
        );
        proof.push(0);
        assert_eq!(
            verify(key.key_data(), &algorithm, MESSAGE, &proof)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData,
            "{}",
            vector.algorithm
        );
    }
}

#[test]
#[cfg(feature = "dsa")]
fn dsa_wire_limits_key_components_and_requires_explicit_signing() {
    use super::signature_algorithm;
    use crate::kex::{decode, fields};

    let vector = VECTORS
        .iter()
        .find(|vector| vector.algorithm == "ssh-dss")
        .unwrap();
    let public = BASE64.decode(vector.public.as_bytes()).unwrap();
    let [name, p, q, g, y] = decode::<5>(&public, None).unwrap();
    let key = decode_public_key(&Algorithm::Dsa, &public).unwrap();
    assert!(signature_algorithm(&key, None, Some("ssh-dss")).is_err());
    assert_eq!(
        signature_algorithm(&key, Some(Algorithm::Dsa), None).unwrap(),
        Algorithm::Dsa
    );
    let mut oversized = [0x69; 130];
    oversized[1] = 0xe0; // Canonical positive mpint with a 1032-bit value.
    oversized[0] = 0;
    let mut smaller = [0x69; 97];
    smaller[1] = 0xe0; // 768-bit DSA import dimensions, unsupported for signing.
    smaller[0] = 0;
    for fields_in in [
        [name, &oversized, q, g, y],
        [name, &smaller, q, &[2], &[4]],
        [name, p, &[2], g, y],
        [name, p, q, &[1], y],
        [name, p, q, g, p],
    ] {
        let malformed = fields(None, &fields_in).unwrap();
        assert_eq!(
            decode_public_key(&Algorithm::Dsa, &malformed)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }
    let wire = BASE64.decode(vector.proof.as_bytes()).unwrap();
    let [name, proof] = decode::<2>(&wire, None).unwrap();
    let short = fields(None, &[name, &proof[1..]]).unwrap();
    assert_eq!(
        verify(key.key_data(), &Algorithm::Dsa, MESSAGE, &short)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
}
