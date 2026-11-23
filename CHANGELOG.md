# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
follow [Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

## [0.2.0] - 2026-11-23

### Changed
- `ssh-key` 0.7.0-rc.12 (was rc.11). Its types are part of the public API
  through `thirtyssh::keys`, so code that also depends on `ssh-key` must move
  to the same release.
- The benchmark-only `_bench` feature uses `criterion` 0.8.

### Removed
- The `nix` development dependency. The PTY example sets non-blocking mode
  with `libc`, which the crate already uses on Unix.

## [0.1.0] - 2026-11-23

### Added
- Initial public version of the `thirtyssh`, `thirtyssh-secretbuf` and
  `thirtyssh-pageant` crates. See the README for the feature list.
