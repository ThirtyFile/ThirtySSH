use super::*;

/// Authorization callbacks receive the claimed username and credential.
/// Password policy should handle storage, rate limits and per-user validation.
pub trait Policy {
    fn password(&mut self, _username: &str, _password: &[u8]) -> bool {
        false
    }
    fn public_key(&mut self, _username: &str, _key: &[u8; 32]) -> bool {
        false
    }
}

/// User authentication methods supported by the server policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMethod {
    PublicKey,
    Password,
    KeyboardInteractive,
}

impl AuthMethod {
    pub fn name(self) -> &'static str {
        match self {
            Self::PublicKey => "publickey",
            Self::Password => "password",
            Self::KeyboardInteractive => "keyboard-interactive",
        }
    }
}

/// A policy decision for an authentication request or a completed factor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthDecision {
    Accept,
    Reject {
        /// Restrict subsequent attempts for this authenticated principal.
        proceed_with_methods: Option<Vec<AuthMethod>>,
        /// The current proof is valid and further authentication is required.
        partial_success: bool,
    },
}

impl AuthDecision {
    pub fn reject() -> Self {
        Self::Reject {
            proceed_with_methods: None,
            partial_success: false,
        }
    }
}

impl From<bool> for AuthDecision {
    fn from(accepted: bool) -> Self {
        if accepted {
            Self::Accept
        } else {
            Self::reject()
        }
    }
}

/// Asynchronous authentication policy for server handlers. All methods deny
/// access by default.
///
/// # State across requests
///
/// A client may change its username between requests. The library then resets
/// its own partial-success and method state, but it does not notify the
/// policy. A policy that remembers which factors a user already passed must
/// key that memory by the `username` argument of every callback, never keep a
/// single connection-wide flag.
pub trait AsyncPolicy {
    /// Choose allowed certificate issuer signatures before user authorization.
    fn certificate_signature_policy(&self) -> CertificateSignaturePolicy {
        CertificateSignaturePolicy::default()
    }

    /// Resolve GEX for this connection before authentication and at rekey.
    fn gex_group_lookup(&self) -> Option<crate::server::GexGroupLookup> {
        None
    }

    fn authentication_banner(&mut self) -> impl Future<Output = io::Result<Option<Banner>>> + Send {
        ready(Ok(None))
    }

    /// The first call has no answers. Subsequent calls contain one UTF-8
    /// answer per prompt, in prompt order, including an empty slice for a
    /// challenge with zero prompts.
    fn keyboard_interactive(
        &mut self,
        _username: &str,
        _submethods: &str,
        _answers: Option<&[&[u8]]>,
    ) -> impl Future<Output = io::Result<InteractiveDecision>> + Send {
        ready(Ok(InteractiveDecision::Finished(AuthDecision::reject())))
    }

    fn none(&mut self, _username: &str) -> impl Future<Output = io::Result<bool>> + Send {
        ready(Ok(false))
    }

    fn password(
        &mut self,
        _username: &str,
        _password: &[u8],
    ) -> impl Future<Output = io::Result<bool>> + Send {
        ready(Ok(false))
    }

    /// Whether this Ed25519 key may log in as `username`. This is a pure
    /// authorization question and is asked more than once per login: for a
    /// client's unsigned offer, and again once the client has proved it holds
    /// the key. Do not record a login here; override `public_key_verified`
    /// for what must happen only after proof.
    fn public_key(
        &mut self,
        _username: &str,
        _key: &[u8; 32],
    ) -> impl Future<Output = io::Result<bool>> + Send {
        ready(Ok(false))
    }

    /// Decide whether to invite a signature for an unsigned public-key probe.
    /// Acceptance here does not authenticate the client.
    fn public_key_offered(
        &mut self,
        username: &str,
        key: &[u8; 32],
    ) -> impl Future<Output = io::Result<bool>> + Send {
        self.public_key(username, key)
    }

    /// Check a typed public key after verifying proof of possession.
    ///
    /// Do not rely on `public_key_probe` having run first; a signed request may
    /// arrive without a probe, so authorize the key here.
    fn public_key_verified(
        &mut self,
        username: &str,
        key: &PublicKey,
    ) -> impl Future<Output = io::Result<bool>> + Send {
        let policy = key
            .key_data()
            .ed25519()
            .map(|key| self.public_key(username, &key.0));
        async move {
            match policy {
                Some(policy) => policy.await,
                None => Ok(false),
            }
        }
    }

    /// Check whether to request proof for a typed public key. The default
    /// delegates Ed25519 to the original policy and declines other keys.
    fn public_key_probe(
        &mut self,
        username: &str,
        key: &PublicKey,
    ) -> impl Future<Output = io::Result<bool>> + Send {
        let policy = key
            .key_data()
            .ed25519()
            .map(|key| self.public_key_offered(username, &key.0));
        async move {
            match policy {
                Some(policy) => policy.await,
                None => Ok(false),
            }
        }
    }

    /// Decide whether to invite proof for a verified user certificate.
    ///
    /// This is an optimization, **not an authorization gate**. A client may
    /// send a signed request without a preceding probe, and by default the
    /// probe is then skipped (see [`Self::check_signed_key_offer`]). Always
    /// repeat the issuer, principal and revocation checks in
    /// [`Self::certificate_verified`].
    fn certificate_probe(
        &mut self,
        _username: &str,
        _certificate: &Certificate,
    ) -> impl Future<Output = io::Result<bool>> + Send {
        ready(Ok(false))
    }

    /// Authorize a certificate after the peer has proved possession of its key.
    ///
    /// The library only proves that the certificate is internally consistent
    /// and that the peer holds its key; a self-signed certificate passes that
    /// check. This callback must decide CA trust, principal mapping and
    /// revocation itself, and must not rely on `certificate_probe` having run.
    fn certificate_verified(
        &mut self,
        _username: &str,
        _certificate: &Certificate,
    ) -> impl Future<Output = io::Result<bool>> + Send {
        ready(Ok(false))
    }

    fn none_decision(
        &mut self,
        username: &str,
    ) -> impl Future<Output = io::Result<AuthDecision>> + Send {
        let decision = self.none(username);
        async move { decision.await.map(AuthDecision::from) }
    }

    fn password_decision(
        &mut self,
        username: &str,
        password: &[u8],
    ) -> impl Future<Output = io::Result<AuthDecision>> + Send {
        let decision = self.password(username, password);
        async move { decision.await.map(AuthDecision::from) }
    }

    fn public_key_decision(
        &mut self,
        username: &str,
        key: &PublicKey,
    ) -> impl Future<Output = io::Result<AuthDecision>> + Send {
        let decision = self.public_key_verified(username, key);
        async move { decision.await.map(AuthDecision::from) }
    }

    fn certificate_decision(
        &mut self,
        username: &str,
        certificate: &Certificate,
    ) -> impl Future<Output = io::Result<AuthDecision>> + Send {
        let decision = self.certificate_verified(username, certificate);
        async move { decision.await.map(AuthDecision::from) }
    }

    fn public_key_offer_decision(
        &mut self,
        username: &str,
        key: &PublicKey,
    ) -> impl Future<Output = io::Result<AuthDecision>> + Send {
        let decision = self.public_key_probe(username, key);
        async move { decision.await.map(AuthDecision::from) }
    }

    fn certificate_offer_decision(
        &mut self,
        username: &str,
        certificate: &Certificate,
    ) -> impl Future<Output = io::Result<AuthDecision>> + Send {
        let decision = self.certificate_probe(username, certificate);
        async move { decision.await.map(AuthDecision::from) }
    }

    /// Require an offer decision for a signed key request that did not follow
    /// a matching accepted probe. The result only controls proof verification.
    fn check_signed_key_offer(&self) -> bool {
        false
    }

    /// Omit password from subsequent failure replies when a password is
    /// rejected without an explicit list of next methods.
    fn hide_rejected_password_method(&self) -> bool {
        false
    }
}

pub(super) struct Synchronous<P>(pub(super) P);

impl<P: Policy> AsyncPolicy for Synchronous<P> {
    fn password(
        &mut self,
        username: &str,
        password: &[u8],
    ) -> impl Future<Output = io::Result<bool>> + Send {
        ready(Ok(self.0.password(username, password)))
    }

    fn public_key(
        &mut self,
        username: &str,
        key: &[u8; 32],
    ) -> impl Future<Output = io::Result<bool>> + Send {
        ready(Ok(self.0.public_key(username, key)))
    }
}
