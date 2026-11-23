# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub private
vulnerability reporting (the "Security" tab, then "Report a vulnerability") on
this repository. Include the affected version or commit, a description, and a
reproduction if you have one.

## Supported versions

Until 1.0 only the latest commit on the default branch receives fixes.

## Scope and known limitations

ThirtySSH is a protocol library; applications own the policy decisions.
Callers should note:

- **Server `AsyncPolicy`:** `public_key_probe` and `certificate_probe` are not
  authorization gates. Check CA trust, principals and revocation in the
  `*_verified` callbacks. The simple `public_key` callback is asked for
  unsigned offers too, so do not record a login there.
- **Host verification:** a client trusts a host only when its
  `Handler::verify_host` returns `true`. The default refuses every host.
- **Strict key exchange:** keep `Kex::StrictClient` and `Kex::StrictServer` in
  custom `TransportPreferences::kex` lists. Omitting them disables the Terrapin
  mitigation.
- **`known_hosts`:** a host known under a different key algorithm reports
  `Unknown`. Do not auto-trust `Unknown` without user confirmation.
- **Forwarding:** the library does not bind sockets for you. Choose loopback
  bind addresses and restrictive Unix socket permissions yourself.
- **Memory locking:** `SecretBuf` locks pages on a best-effort basis. A failure
  to lock is silent.
- **Idle sessions:** `inactivity_timeout` ignores keepalives and replies, so
  it ends a session nobody uses even while keepalives are answered.
- **Agent pipes on Windows:** `Client::named_pipe` talks only to a pipe owned
  by the current account or by the system.
- **Group exchange:** during `diffie-hellman-group-exchange` the client
  proves that the server's modulus is a safe prime. The proof runs on a
  blocking thread (inline on wasm) and costs CPU for every handshake and
  rekey. In unoptimized builds it can exceed the default handshake timeout.
  Exclude `Kex::DhGexSha256` and `Kex::DhGexSha1` for untrusted servers.
