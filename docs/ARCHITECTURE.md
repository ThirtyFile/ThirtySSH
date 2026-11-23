# Architecture

The `thirtyssh` crate is layered. Each layer builds on the ones listed before
it.

1. **`wire`, `clear_packet`, `identification`, `initial`**: SSH wire encoding,
   the unencrypted packet format, version exchange and KEXINIT negotiation
   (including strict key exchange).
2. **`kex`, `algorithms`, `protection`, `compression`**: key exchange methods,
   algorithm preferences, the encrypted packet codecs (AEAD, CTR, CBC, Etm
   MACs) and optional compression.
3. **`transport`**: an encrypted stream after mutual NEWKEYS. Its submodules
   hold the initial handshake, rekeying (byte, time and peer initiated), the
   queue of packets read while a write or a rekey is in progress, rekey
   limits and disconnect messages. A `failed` flag makes the transport
   unusable after an interrupted operation.
4. **`auth`**: client and server user authentication on top of a transport.
   Servers implement `Policy` or `AsyncPolicy`.
5. **`channel`**: channel table, windows, and the `Driver` that multiplexes
   channels over one authenticated transport. `channel::stream` provides the
   `AsyncRead`/`AsyncWrite` view of a channel.
6. **`session`, `client`, `server`**: high level front ends with configuration,
   `Handler` callbacks, keepalive and inactivity handling
   (`session::liveness`), and graceful shutdown.
7. **`exec`, `forward`, `pty`**: helpers for commands, port and streamlocal
   forwarding, and pseudo-terminal requests.

Cross-cutting modules:

- **`keys`**: key types, parsers (`keys::format`), certificates, and the agent
  client and server (`keys::agent`).
- **`known_hosts`**: known-hosts file handling and updates.
- **`runtime`**: thin Tokio/wasm abstraction for timers and spawning.

## Other crates

- `thirtyssh-secretbuf`: page-locked (`mlock` / `VirtualLock`) buffer that is
  zeroized on drop and when it shrinks or reallocates.
- `thirtyssh-pageant`: Windows-only Pageant client using named pipes and the
  legacy `WM_COPYDATA` shared-memory protocol.

## Concurrency model

A session runs as one task. Inside it the `Driver` (I/O, flow control,
liveness) and the user's `Handler` callbacks are polled in a `select!` loop.
Callbacks run one at a time, so work that lasts as long as a channel belongs
in a spawned task. When the driver stops, queued events are drained to the
handler for up to `shutdown_timeout`.

Events wait for the handler in a bounded queue. The driver keeps reading a
little past a full queue, so that channel data, window adjustments, replies
and open confirmations are not held up behind events, and then stops reading
until a callback returns. While a callback awaits a global reply the driver
reads further, within a fixed budget, and aborts the connection if a peer
floods past it: the callback is the consumer of the event queue, so waiting
would deadlock.

Each channel with its own reader has a mailbox bounded by its receive window.
Small packets beyond a fixed count are joined, so a window filled one byte at
a time does not cost a queue entry per byte.

When the connection fails, what the peer had already sent on a channel (data,
EOF, close, an exit status) is still delivered to that channel's reader.
