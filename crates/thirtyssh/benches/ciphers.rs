//! Packet cipher throughput. Run with
//! `cargo bench -p thirtyssh --features _bench`.
use criterion::{criterion_group, criterion_main};

criterion_group!(benches, thirtyssh::benchmark::bench);
criterion_main!(benches);
