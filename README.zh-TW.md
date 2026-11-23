# ThirtySSH

[![CI](https://github.com/thirtyfile/ThirtySSH/actions/workflows/ci.yml/badge.svg)](https://github.com/thirtyfile/ThirtySSH/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/thirtyssh.svg)](https://crates.io/crates/thirtyssh)
[![docs.rs](https://docs.rs/thirtyssh/badge.svg)](https://docs.rs/thirtyssh)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[English](README.md) | [简体中文](README.zh-CN.md) | **繁體中文**

以 Tokio 為基礎的 Rust 非同步 SSH-2 用戶端與伺服器函式庫。
這是獨立實作的專案,採分層設計:可以直接使用高階的用戶端與伺服器,
也可以只取用傳輸、認證或通道這些底層。

> **狀態:** 尚未到 1.0,API 可能在次要版本之間變動。
> 用於正式環境前請先閱讀 [SECURITY.md](SECURITY.md)。

## 功能

- 用戶端與伺服器,多工通道與流量控制
- 金鑰交換:ML-KEM-768 + X25519 混合、Curve25519、NIST P-256/384/521、
  DH group exchange 與固定群組;strict key exchange(緩解 Terrapin 攻擊)
- 加密演算法:ChaCha20-Poly1305、AES-GCM、AES-CTR,以及給舊版對端用的 AES-CBC
- 公鑰、密碼、keyboard-interactive 認證,OpenSSH 使用者與主機憑證,GSSAPI 掛鉤
- 金鑰格式:OpenSSH、PKCS#1/#8(含加密)、PuTTY `.ppk`
- `known_hosts` 的解析、比對與更新(雜湊主機名、`@cert-authority`、`@revoked`)
- SSH agent 用戶端與伺服器、agent 轉發、Windows Pageant
- 連接埠轉發、streamlocal(Unix socket)轉發、PTY 輔助、`exec`
- Keepalive 與閒置逾時處理

## 安裝

從 crates.io 加入 ThirtySSH:

```toml
[dependencies]
thirtyssh = "0.1"
tokio = { version = "1", features = ["macros", "rt"] }
```

最低支援的 Rust 版本是 1.89。CI 會在 Linux、Windows 與 macOS 上測試。

## 範例

連線、用 `known_hosts` 驗證主機、以金鑰登入並執行一個指令:

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

只有 `verify_host` 回傳 `true` 時主機才會被信任;預設會拒絕所有主機。
完整的程式(包含一個帶有虛擬終端的伺服器)放在
[`crates/thirtyssh/examples`](crates/thirtyssh/examples):

```sh
cargo run -p thirtyssh --example openssh_exec -- \
  HOST 22 USER ~/.ssh/known_hosts ~/.ssh/id_ed25519 "uname -a"
```

API 文件在 [docs.rs](https://docs.rs/thirtyssh)。

## Cargo feature

| Feature | 預設 | 用途 |
|---|---|---|
| `ring` | 開 | 密碼學後端(`ring` 與 `aws-lc-rs` 至少要開一個) |
| `aws-lc-rs` | 關 | 另一個密碼學後端,兩者都開時使用它 |
| `rsa` | 開 | RSA 金鑰與簽章 |
| `flate2` | 開 | `zlib` 與 `zlib@openssh.com` 壓縮 |
| `dsa` | 關 | 舊式 DSA 金鑰 |
| `des` | 關 | 舊式 `3des-cbc` 加密與 3DES 加密的金鑰檔 |
| `serde` | 關 | 金鑰型別的 `serde` 支援 |
| `pre-rfc8410-ed25519` | 關 | RFC 8410 之前的 PKCS#8 Ed25519 金鑰編碼 |

## 目錄結構

| 路徑 | Crate | 用途 |
|---|---|---|
| `crates/thirtyssh` | `thirtyssh` | SSH 函式庫本體 |
| `crates/secretbuf` | `thirtyssh-secretbuf` | 鎖定記憶體頁面、釋放時清除內容的位元組緩衝區 |
| `crates/pageant` | `thirtyssh-pageant` | Pageant 用戶端(僅 Windows) |
| `tools/` | | 互通測試用的輔助腳本 |
| `docs/` | | 架構說明 |

## 開發

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo deny check
```

與真實 OpenSSH 的互通測試標為 `#[ignore]`,在 CI 的 Linux 環境執行。
詳見 [CONTRIBUTING.md](CONTRIBUTING.md) 與
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 授權

Apache-2.0,見 [LICENSE](LICENSE)。
