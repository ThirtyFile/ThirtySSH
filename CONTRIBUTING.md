# Contributing

Thanks for your interest. Issues and pull requests are welcome.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
cargo deny check
```

- The minimum supported Rust version is 1.89 (`rust-version` in `Cargo.toml`).
  CI checks it.
- Add a test for every bug fix. A regression test should fail without the fix.
- Keep `#![forbid(unsafe_code)]` in the `thirtyssh` crate. `unsafe` belongs in
  `secretbuf` and `pageant` and needs a `// SAFETY:` comment.
- Do not `unwrap`, `expect` or `panic!` on data that comes from the network.
- Update `CHANGELOG.md` under "Unreleased".

## Interoperability tests

Tests that need real OpenSSH binaries are `#[ignore]`d and run in CI on
Linux. To run them locally:

```sh
# OpenSSH client (`ssh`, `ssh-keygen`) against a ThirtySSH server
cargo test -p thirtyssh --test openssh -- --ignored

# ThirtySSH client against a disposable `sshd` on loopback. Run as root (or
# as the login account itself); USER must be an unlocked, non-root account
# that can read the toolchain and write the checkout.
python3 tools/run_openssh_server.py --user USER

# The same without root: USER starts an extracted sshd inside a Bubblewrap
# sandbox. DIR holds an unpacked openssh-server package, for example from
# `apt-get download openssh-server && dpkg-deb -x openssh-server_*.deb DIR`.
python3 tools/run_openssh_server.py --user USER --image DIR
```

The remaining ignored tests name their requirement in the `#[ignore]` reason
(for example PuTTY's `puttygen`, or a Pageant instance on Windows).

## Layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

By contributing you agree that your contribution is licensed under
Apache-2.0.

## Releasing

Maintainers publish a release by tagging the version that `Cargo.toml`
declares:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The `Release` workflow tests the workspace, publishes the three crates to
crates.io in dependency order and creates the GitHub release. Update
`CHANGELOG.md` and the version in `Cargo.toml` before tagging. A published
version cannot be replaced.
