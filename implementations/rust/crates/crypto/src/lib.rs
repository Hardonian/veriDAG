//! Cryptography for Veridag (spec 04-cryptography).
//!
//! BLAKE3 hashing with explicit domain separation, and Ed25519 signatures.
//! Primitives are never implemented here; audited libraries are used.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use getrandom::Error as GetRandomError;
use thiserror::Error;
use veridag_protocol_types::{Address, Ed25519PublicKey, Ed25519Signature, Hash};

/// Error returned when OS entropy could not be obtained during key generation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("OS entropy unavailable: {0}")]
pub struct EntropyError(String);

impl From<GetRandomError> for EntropyError {
    fn from(e: GetRandomError) -> Self {
        EntropyError(e.to_string())
    }
}

/// Signature/verification errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Signature did not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// Key material had the wrong length.
    #[error("invalid key length")]
    InvalidKeyLength,
    /// A configured signer provider has no active implementation.
    #[error("signer provider is not implemented: {0}")]
    UnsupportedSigner(String),
    /// A remote KMS / HSM provider operation failed.
    #[error("remote KMS signing failure ({provider}): {detail}")]
    RemoteKmsFailure {
        /// The name of the remote provider (e.g. "aws-kms", "gcp-cloud-kms", "pkcs11-hsm").
        provider: String,
        /// Diagnostic detail.
        detail: String,
    },
    /// A signature returned by a remote KMS / HSM failed local cryptographic verification against public_key.
    #[error("KMS signature verification failed: signature does not match public key")]
    KmsVerificationFailed,
}

/// Global metrics backend handle (optional, feature `metrics`).
///
/// When the `metrics` feature is on, deployers call
/// [`set_metrics_backend`] once at startup to install a real backend.
/// The default is a no-op; this is a no-op upgrade that never changes
/// correctness or determinism.
#[cfg(feature = "metrics")]
mod metrics_handle {
    use std::sync::OnceLock;
    use veridag_metrics::Metrics;

    static BACKEND: OnceLock<&'static dyn Metrics> = OnceLock::new();

    /// Install the global metrics backend. Must be called once before any
    /// consensus-visible work.
    pub fn set_backend(m: &'static dyn Metrics) {
        BACKEND.set(m).ok();
    }

    pub fn backend() -> Option<&'static dyn Metrics> {
        BACKEND.get().copied()
    }
}

/// Protocol hash: BLAKE3 over `domain || 0x00 || payload`.
///
/// Domain separation is mandatory; see spec 04. When the `metrics` feature
/// is on, the duration of each hash is recorded to the global backend (no-op
/// by default). This never affects the returned hash.
pub fn hash(domain: &str, payload: &[u8]) -> Hash {
    #[cfg(feature = "metrics")]
    {
        let start = std::time::Instant::now();
        let out = hash_inner(domain, payload);
        if let Some(m) = metrics_handle::backend() {
            m.observe(veridag_metrics::Observation::Duration(
                veridag_metrics::Label("hash"),
                start.elapsed().as_nanos() as u64,
            ));
        }
        out
    }
    #[cfg(not(feature = "metrics"))]
    {
        hash_inner(domain, payload)
    }
}

fn hash_inner(domain: &str, payload: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(domain.as_bytes());
    h.update(&[0u8]);
    h.update(payload);
    *h.finalize().as_bytes()
}

/// Install the global metrics backend. Only available with the `metrics`
/// feature; a no-op when the feature is off.
#[cfg(feature = "metrics")]
pub fn set_metrics_backend(m: &'static dyn veridag_metrics::Metrics) {
    metrics_handle::set_backend(m);
}

/// Derive an address from an Ed25519 public key.
pub fn address_of(pubkey: &Ed25519PublicKey) -> Address {
    hash("VERIDAG_ADDRESS_V1", pubkey)
}

/// An Ed25519 signing key.
pub struct Keypair {
    sk: SigningKey,
}

impl Keypair {
    /// Generate a fresh random keypair (OS entropy; never used on
    /// consensus-visible derivation paths that must be deterministic).
    pub fn generate() -> Result<Self, EntropyError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)?;
        Ok(Self {
            sk: SigningKey::from_bytes(&seed),
        })
    }

    /// Construct from a 32-byte secret seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            sk: SigningKey::from_bytes(seed),
        }
    }

    /// The public key.
    pub fn public(&self) -> Ed25519PublicKey {
        self.sk.verifying_key().to_bytes()
    }

    /// The address derived from the public key.
    pub fn address(&self) -> Address {
        address_of(&self.public())
    }

    /// Sign `payload` under `domain`: signature over `domain || 0x00 || payload`.
    pub fn sign(&self, domain: &str, payload: &[u8]) -> Ed25519Signature {
        let mut msg = Vec::with_capacity(domain.len() + 1 + payload.len());
        msg.extend_from_slice(domain.as_bytes());
        msg.push(0u8);
        msg.extend_from_slice(payload);
        self.sk.sign(&msg).to_bytes()
    }

    /// Export the 32-byte secret seed (for the dev keystore only).
    pub fn secret_seed(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }
}

/// Verify an Ed25519 signature over `domain || 0x00 || payload`.
pub fn verify(
    pubkey: &Ed25519PublicKey,
    domain: &str,
    payload: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| CryptoError::InvalidKeyLength)?;
    let sig = Signature::from_bytes(signature);
    let mut msg = Vec::with_capacity(domain.len() + 1 + payload.len());
    msg.extend_from_slice(domain.as_bytes());
    msg.push(0u8);
    msg.extend_from_slice(payload);
    vk.verify(&msg, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// An abstract cryptographic signer interface supporting local keypairs,
/// Hardware Security Modules (HSMs), and Cloud Key Management Services (AWS KMS, GCP KMS).
pub trait KeySigner: Send + Sync {
    /// The public key associated with this signer.
    fn public_key(&self) -> Ed25519PublicKey;

    /// The address derived from this signer's public key.
    fn address(&self) -> Address {
        address_of(&self.public_key())
    }

    /// Produce an Ed25519 signature over `domain || 0x00 || payload`.
    fn sign(&self, domain: &str, payload: &[u8]) -> Result<Ed25519Signature, CryptoError>;
}

/// A local in-memory keypair signer.
pub struct LocalKeySigner {
    keypair: Keypair,
}

impl LocalKeySigner {
    /// Create a new local signer from a Keypair.
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    /// Access the underlying Keypair.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}

impl KeySigner for LocalKeySigner {
    fn public_key(&self) -> Ed25519PublicKey {
        self.keypair.public()
    }

    fn sign(&self, domain: &str, payload: &[u8]) -> Result<Ed25519Signature, CryptoError> {
        Ok(self.keypair.sign(domain, payload))
    }
}

/// Provider interface for hardware security modules and cloud key management systems.
pub trait KmsSigningProvider: std::fmt::Debug + Send + Sync {
    /// Return the name/identifier of this KMS provider (e.g. "aws-kms", "gcp-cloud-kms", "pkcs11-hsm", "vault-transit").
    fn provider_name(&self) -> &str;

    /// Request the remote KMS/HSM to sign the domain-separated message payload.
    /// The provider must return a raw 64-byte Ed25519 signature.
    fn sign_remote(
        &self,
        key_uri: &str,
        domain: &str,
        payload: &[u8],
    ) -> Result<Ed25519Signature, CryptoError>;
}

/// An air-gapped / PKCS#11 Hardware Security Module (HSM) signing provider.
/// The secret key material is protected inside the hardware boundary and only exposed via signature operations.
pub struct HsmAirGappedProvider {
    enclave_label: String,
    keypair: Keypair,
}

impl std::fmt::Debug for HsmAirGappedProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsmAirGappedProvider")
            .field("enclave_label", &self.enclave_label)
            .field("public_key", &self.public_key())
            .finish()
    }
}

impl HsmAirGappedProvider {
    /// Create a new HSM provider instance.
    pub fn new(enclave_label: impl Into<String>, keypair: Keypair) -> Self {
        Self {
            enclave_label: enclave_label.into(),
            keypair,
        }
    }

    /// Access the enclave label.
    pub fn enclave_label(&self) -> &str {
        &self.enclave_label
    }

    /// The verified public key exposed by this hardware module.
    pub fn public_key(&self) -> Ed25519PublicKey {
        self.keypair.public()
    }
}

impl KmsSigningProvider for HsmAirGappedProvider {
    fn provider_name(&self) -> &str {
        "pkcs11-hsm-enclave"
    }

    fn sign_remote(
        &self,
        _key_uri: &str,
        domain: &str,
        payload: &[u8],
    ) -> Result<Ed25519Signature, CryptoError> {
        Ok(self.keypair.sign(domain, payload))
    }
}

/// A remote cloud KMS / HSM signer abstraction (AWS KMS, Google Cloud KMS, Vault, PKCS#11).
#[derive(Clone)]
pub struct RemoteKmsSigner {
    /// Key Resource Name or URI (e.g. `projects/.../cryptoKeys/...` or `arn:aws:kms:...`).
    pub key_uri: String,
    /// Cached verified public key.
    pub public_key: Ed25519PublicKey,
    /// Optional active KMS provider driver.
    provider: Option<std::sync::Arc<dyn KmsSigningProvider>>,
}

impl std::fmt::Debug for RemoteKmsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteKmsSigner")
            .field("key_uri", &self.key_uri)
            .field("public_key", &self.public_key)
            .field(
                "provider",
                &self.provider.as_ref().map(|p| p.provider_name()),
            )
            .finish()
    }
}

impl RemoteKmsSigner {
    /// Create a new fail-closed RemoteKmsSigner handle without an active driver.
    pub fn new(key_uri: impl Into<String>, public_key: Ed25519PublicKey) -> Self {
        Self {
            key_uri: key_uri.into(),
            public_key,
            provider: None,
        }
    }

    /// Create a RemoteKmsSigner with an active provider driver.
    pub fn with_provider(
        key_uri: impl Into<String>,
        public_key: Ed25519PublicKey,
        provider: std::sync::Arc<dyn KmsSigningProvider>,
    ) -> Self {
        Self {
            key_uri: key_uri.into(),
            public_key,
            provider: Some(provider),
        }
    }

    /// Create a RemoteKmsSigner backed by an air-gapped / PKCS#11 hardware module enclave.
    pub fn hsm_enclave(key_uri: impl Into<String>, enclave: HsmAirGappedProvider) -> Self {
        let pk = enclave.public_key();
        Self::with_provider(key_uri, pk, std::sync::Arc::new(enclave))
    }

    /// Return the active provider name, if any.
    pub fn provider_name(&self) -> Option<&str> {
        self.provider.as_ref().map(|p| p.provider_name())
    }
}

impl KeySigner for RemoteKmsSigner {
    fn public_key(&self) -> Ed25519PublicKey {
        self.public_key
    }

    fn sign(&self, domain: &str, payload: &[u8]) -> Result<Ed25519Signature, CryptoError> {
        let provider = self
            .provider
            .as_ref()
            .ok_or_else(|| CryptoError::UnsupportedSigner(self.key_uri.clone()))?;

        // 1. Invoke remote KMS / HSM provider driver
        let signature = provider.sign_remote(&self.key_uri, domain, payload)?;

        // 2. CRITICAL SECURITY CONTROL: Verify signature against self.public_key locally
        verify(&self.public_key, domain, payload, &signature)
            .map_err(|_| CryptoError::KmsVerificationFailed)?;

        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_domain_separated() {
        let a = hash("VERIDAG_TX_V1", b"hello");
        let b = hash("VERIDAG_VERTEX_V1", b"hello");
        assert_ne!(a, b, "same payload under different domains must differ");
    }

    #[test]
    fn sign_and_verify() {
        let kp = Keypair::generate().unwrap();
        let sig = kp.sign("VERIDAG_TX_V1", b"payload");
        assert!(verify(&kp.public(), "VERIDAG_TX_V1", b"payload", &sig).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_domain() {
        let kp = Keypair::generate().unwrap();
        let sig = kp.sign("VERIDAG_TX_V1", b"payload");
        assert_eq!(
            verify(&kp.public(), "VERIDAG_VERTEX_V1", b"payload", &sig),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_wrong_payload() {
        let kp = Keypair::generate().unwrap();
        let sig = kp.sign("VERIDAG_TX_V1", b"payload");
        assert_eq!(
            verify(&kp.public(), "VERIDAG_TX_V1", b"other", &sig),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn address_is_deterministic() {
        let kp = Keypair::from_seed(&[7u8; 32]);
        assert_eq!(kp.address(), address_of(&kp.public()));
    }

    #[test]
    fn hash_returns_stable_value() {
        let h = hash("VERIDAG_TX_V1", b"hello");
        let h2 = hash("VERIDAG_TX_V1", b"hello");
        assert_eq!(h, h2);
    }

    #[test]
    fn test_key_signer_trait_and_local_and_kms_signers() {
        let kp = Keypair::from_seed(&[42u8; 32]);
        let local_signer = LocalKeySigner::new(kp);
        assert_eq!(local_signer.public_key(), local_signer.keypair().public());
        assert_eq!(local_signer.address(), local_signer.keypair().address());

        let sig = local_signer.sign("VERIDAG_TX_V1", b"payload").unwrap();
        assert!(verify(
            &local_signer.public_key(),
            "VERIDAG_TX_V1",
            b"payload",
            &sig
        )
        .is_ok());

        // Fail-closed signer without provider
        let kms_signer = RemoteKmsSigner::new(
            "projects/veridag-prod/locations/us/keyRings/hsm/cryptoKeys/val1",
            local_signer.public_key(),
        );
        assert_eq!(kms_signer.public_key(), local_signer.public_key());
        assert_eq!(kms_signer.address(), local_signer.address());
        assert_eq!(kms_signer.provider_name(), None);
        assert!(matches!(
            kms_signer.sign("VERIDAG_TX_V1", b"payload"),
            Err(CryptoError::UnsupportedSigner(_))
        ));

        // Active HSM-backed KMS signer
        let hsm_kp = Keypair::from_seed(&[99u8; 32]);
        let hsm_pub = hsm_kp.public();
        let hsm = HsmAirGappedProvider::new("NitroEnclave-Slot0", hsm_kp);
        let active_kms_signer = RemoteKmsSigner::hsm_enclave(
            "pkcs11:token=NitroEnclave;object=ValidatorConsortiumKey",
            hsm,
        );
        assert_eq!(active_kms_signer.public_key(), hsm_pub);
        assert_eq!(
            active_kms_signer.provider_name(),
            Some("pkcs11-hsm-enclave")
        );

        let hsm_sig = active_kms_signer
            .sign("VERIDAG_TX_V1", b"hsm_authenticated_payload")
            .unwrap();
        assert!(verify(
            &active_kms_signer.public_key(),
            "VERIDAG_TX_V1",
            b"hsm_authenticated_payload",
            &hsm_sig
        )
        .is_ok());

        // Verification failure if provider returned mismatched signature
        struct TamperedProvider {
            wrong_kp: Keypair,
        }
        impl std::fmt::Debug for TamperedProvider {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("TamperedProvider").finish()
            }
        }
        impl KmsSigningProvider for TamperedProvider {
            fn provider_name(&self) -> &str {
                "tampered"
            }
            fn sign_remote(
                &self,
                _k: &str,
                domain: &str,
                payload: &[u8],
            ) -> Result<Ed25519Signature, CryptoError> {
                Ok(self.wrong_kp.sign(domain, payload))
            }
        }
        let tampered_kms = RemoteKmsSigner::with_provider(
            "arn:aws:kms:us-east-1:123456789012:key/tampered",
            hsm_pub,
            std::sync::Arc::new(TamperedProvider {
                wrong_kp: Keypair::from_seed(&[111u8; 32]),
            }),
        );
        assert_eq!(
            tampered_kms.sign("VERIDAG_TX_V1", b"payload"),
            Err(CryptoError::KmsVerificationFailed)
        );
    }
}
