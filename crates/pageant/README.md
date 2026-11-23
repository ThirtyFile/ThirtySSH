# thirtyssh-pageant

A client stream to the PuTTY Pageant SSH agent on Windows. It carries the SSH
agent protocol over Pageant's named pipe, or over the older `WM_COPYDATA`
window message, and checks that the agent belongs to the current account
before sending anything.

On other platforms the crate is empty.

This crate is part of [ThirtySSH](https://github.com/thirtyfile/ThirtySSH),
which provides the agent protocol itself.

## License

Apache-2.0.
