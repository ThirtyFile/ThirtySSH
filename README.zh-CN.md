# ThirtySSH

[![CI](https://github.com/thirtyfile/ThirtySSH/actions/workflows/ci.yml/badge.svg)](https://github.com/thirtyfile/ThirtySSH/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/thirtyssh.svg)](https://crates.io/crates/thirtyssh)
[![docs.rs](https://docs.rs/thirtyssh/badge.svg)](https://docs.rs/thirtyssh)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[English](README.md) | **简体中文** | [繁體中文](README.zh-TW.md)

基于 Tokio 的 Rust 异步 SSH-2 客户端与服务器库。
这是一个独立实现的项目,采用分层设计:可以直接使用高层的客户端与服务器,
也可以只使用传输、认证或通道这些底层。

> **状态:** 尚未到 1.0,API 可能在次要版本之间变动。
> 用于生产环境前请先阅读 [SECURITY.md](SECURITY.md)。

## 功能

- 客户端与服务器,多路复用通道与流量控制
- 密钥交换:ML-KEM-768 + X25519 混合、Curve25519、NIST P-256/384/521、
  DH group exchange 与固定群组;strict key exchange(缓解 Terrapin 攻击)
- 加密算法:ChaCha20-Poly1305、AES-GCM、AES-CTR,以及为旧版对端保留的 AES-CBC
- 公钥、密码、keyboard-interactive 认证,OpenSSH 用户与主机证书,GSSAPI 钩子
- 密钥格式:OpenSSH、PKCS#1/#8(含加密)、PuTTY `.ppk`
- `known_hosts` 的解析、匹配与更新(哈希主机名、`@cert-authority`、`@revoked`)
- SSH agent 客户端与服务器、agent 转发、Windows Pageant
- 端口转发、streamlocal(Unix socket)转发、PTY 辅助、`exec`
- Keepalive 与空闲超时处理

## 安装

从 crates.io 添加 ThirtySSH:

```toml
[dependencies]
thirtyssh = "0.1"
tokio = { version = "1", features = ["macros", "rt"] }
```

最低支持的 Rust 版本是 1.89。CI 会在 Linux、Windows 与 macOS 上测试。

## 示例

连接、用 `known_hosts` 验证主机、以密钥登录并执行一条命令:

```rust
use std::{io, sync::Arc};
use thirtyssh::{
    client::{self, Method},
    exec,
    keys::{Algorithm, Credential, PrivateKeyReader},
    known_hosts::{KnownHosts, Status},
    session,
};

struct Known(KnownHosts);

impl session::Handler for Known {}

impl client::Handler for Known {
    async fn verify_host(&mut self, host: &Credential, _: &Algorithm) -> io::Result<bool> {
        let status = match host {
            Credential::Key(key) => self.0.check_public_key("example.com", 22, key)?,
            Credential::Certificate(cert) => self.0.check_certificate("example.com", 22, cert)?,
        };
        Ok(status == Status::Trusted)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let mut hosts = KnownHosts::new();
    hosts.load("/home/me/.ssh/known_hosts")?;
    let config = Arc::new(client::Config::default());
    let mut client = client::connect(config, ("example.com", 22), Known(hosts)).await?;

    let key = PrivateKeyReader::new().file("/home/me/.ssh/id_ed25519")?;
    let method = Method::Key { key: &key, algorithm: None };
    if !client.authenticate("me", method).await?.is_accepted() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "login rejected"));
    }

    let session = client.start()?;
    let output = exec::start(&session.handle(), b"uname -a")
        .await?
        .capture(tokio::io::empty(), 1024 * 1024)
        .await?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    session.disconnect().await
}
```

只有 `verify_host` 返回 `true` 时主机才会被信任;默认拒绝所有主机。
完整的程序(包括一个带伪终端的服务器)位于
[`crates/thirtyssh/examples`](crates/thirtyssh/examples):

```sh
cargo run -p thirtyssh --example openssh_exec -- \
  HOST 22 USER ~/.ssh/known_hosts ~/.ssh/id_ed25519 "uname -a"
```

API 文档在 [docs.rs](https://docs.rs/thirtyssh)。

## Cargo feature

| Feature | 默认 | 用途 |
|---|---|---|
| `ring` | 开 | 密码学后端(`ring` 与 `aws-lc-rs` 至少要开一个) |
| `aws-lc-rs` | 关 | 另一个密码学后端,两者都开时使用它 |
| `rsa` | 开 | RSA 密钥与签名 |
| `flate2` | 开 | `zlib` 与 `zlib@openssh.com` 压缩 |
| `dsa` | 关 | 旧式 DSA 密钥 |
| `des` | 关 | 旧式 `3des-cbc` 加密与 3DES 加密的密钥文件 |
| `serde` | 关 | 密钥类型的 `serde` 支持 |
| `pre-rfc8410-ed25519` | 关 | RFC 8410 之前的 PKCS#8 Ed25519 密钥编码 |

## 目录结构

| 路径 | Crate | 用途 |
|---|---|---|
| `crates/thirtyssh` | `thirtyssh` | SSH 库本体 |
| `crates/secretbuf` | `thirtyssh-secretbuf` | 锁定内存页、释放时清除内容的字节缓冲区 |
| `crates/pageant` | `thirtyssh-pageant` | Pageant 客户端(仅 Windows) |
| `tools/` | | 互操作测试用的辅助脚本 |
| `docs/` | | 架构说明 |

## 开发

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo deny check
```

与真实 OpenSSH 的互操作测试标为 `#[ignore]`,在 CI 的 Linux 环境中运行。
详见 [CONTRIBUTING.md](CONTRIBUTING.md) 与
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 许可

Apache-2.0,见 [LICENSE](LICENSE)。
