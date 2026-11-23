# thirtyssh-secretbuf

A growable byte buffer for secret material. Its memory is locked into RAM
where the platform allows (`mlock` on Unix, `VirtualLock` on Windows) and is
erased when the buffer shrinks, reallocates or is dropped.

Page locking is best effort: when the operating system refuses, the buffer
still works and still erases its contents.

This crate is part of [ThirtySSH](https://github.com/thirtyfile/ThirtySSH).

## License

Apache-2.0.
