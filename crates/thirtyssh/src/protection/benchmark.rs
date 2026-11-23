use super::{AEAD_TAG, DirectionKeys, Gcm, LENGTH_SIZE, aead, chacha};
use criterion::{BatchSize, Criterion, Throughput};
use ssh_key::rand_core::TryRng;
use std::hint::black_box;

/// Benchmark the negotiated OpenSSH AEAD packet ciphers.
pub fn bench(criterion: &mut Criterion) {
    bench_cipher(
        criterion,
        "chacha20-poly1305@openssh.com",
        |keys| {
            (
                chacha::SealingKey::new(&keys.cipher),
                chacha::OpeningKey::new(&keys.cipher),
            )
        },
        |(seal, open), sequence, frame, tag| {
            seal.seal_in_place(sequence, frame, tag);
            open.open_in_place(sequence, frame, tag)
                .expect("ChaCha20-Poly1305 benchmark packet");
        },
    );
    bench_cipher(
        criterion,
        "aes256-gcm@openssh.com",
        |keys| {
            (
                Gcm::new(&aead::AES_256_GCM, keys),
                Gcm::new(&aead::AES_256_GCM, keys),
            )
        },
        |(seal, open), _, frame, tag| {
            seal.seal(frame, tag).expect("AES-GCM benchmark seal");
            open.open(frame, tag).expect("AES-GCM benchmark open");
        },
    );
}

fn bench_cipher<Keys>(
    criterion: &mut Criterion,
    name: &str,
    setup: impl Fn(&DirectionKeys) -> Keys,
    round_trip: impl Fn(&mut Keys, u32, &mut [u8], &mut [u8; AEAD_TAG]),
) {
    let mut group = criterion.benchmark_group(format!("Cipher: {name}"));
    for size in [100usize, 1000, 10000] {
        let packets = 10_000 / size;
        group.throughput(Throughput::Bytes((size * packets) as u64));
        group.bench_function(format!("Block size: {size}"), |bencher| {
            bencher.iter_batched(
                || {
                    let mut keys = DirectionKeys::unused();
                    getrandom::SysRng
                        .try_fill_bytes(keys.cipher.as_mut())
                        .expect("benchmark key randomness");
                    let mut frame = vec![0; LENGTH_SIZE + size];
                    frame[..LENGTH_SIZE].copy_from_slice(&(size as u32).to_be_bytes());
                    (setup(&keys), frame)
                },
                |(mut keys, mut frame)| {
                    let mut tag = [0; AEAD_TAG];
                    for sequence in 0..packets as u32 {
                        round_trip(&mut keys, sequence, &mut frame, &mut tag);
                    }
                    black_box(frame);
                },
                BatchSize::SmallInput,
            );
        });
    }
}
