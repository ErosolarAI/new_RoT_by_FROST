//! Traits for hardware abstraction

use crate::{HardwareError, HardwareResult};
use frost_core::{SecretShare, ParticipantId, SigningCommitment, PartialSignature};
use serde::{Serialize, Deserialize};

#[cfg(feature = "std")]
use async_trait::async_trait;

/// Secure element capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureElementInfo {
    /// Manufacturer name
    pub manufacturer: String,
    /// Model number
    pub model: String,
    /// Firmware version
    pub firmware_version: String,
    /// Hardware serial number
    pub serial_number: [u8; 16],
    /// Supported features
    pub features: SecureElementFeatures,
}

/// Feature flags for secure element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureElementFeatures {
    /// Hardware random number generator
    pub has_trng: bool,
    /// Hardware AES acceleration
    pub has_aes: bool,
    /// Hardware ECC acceleration
    pub has_ecc: bool,
    /// Secure boot capability
    pub has_secure_boot: bool,
    /// TrustZone or equivalent
    pub has_trustzone: bool,
    /// Physical unclonable function
    pub has_puf: bool,
    /// Tamper detection
    pub has_tamper_detection: bool,
}

/// Core trait for secure element operations
#[cfg(feature = "std")]
#[async_trait]
pub trait SecureElement: Send + Sync {
    /// Initialize the hardware
    async fn initialize(&mut self) -> HardwareResult<()>;

    /// Get hardware information
    async fn get_info(&self) -> HardwareResult<SecureElementInfo>;

    /// Generate cryptographically secure random bytes
    async fn random_bytes(&self, buffer: &mut [u8]) -> HardwareResult<()>;

    /// Store secret share securely
    async fn store_share(&mut self, share_id: &str, share: &SecretShare) -> HardwareResult<()>;

    /// Load secret share
    async fn load_share(&self, share_id: &str) -> HardwareResult<SecretShare>;

    /// Delete secret share (with secure erasure)
    async fn delete_share(&mut self, share_id: &str) -> HardwareResult<()>;

    /// Perform FROST Round 1 (generate signing commitment)
    async fn signing_round1(
        &self,
        share_id: &str,
        session_id: &[u8],
    ) -> HardwareResult<SigningCommitment>;

    /// Perform FROST Round 2 (generate partial signature)
    async fn signing_round2(
        &self,
        share_id: &str,
        session_id: &[u8],
        message: &[u8],
        commitments: &[SigningCommitment],
    ) -> HardwareResult<PartialSignature>;

    /// Get hardware attestation
    async fn get_attestation(&self) -> HardwareResult<Attestation>;

    /// Perform self-test
    async fn self_test(&self) -> HardwareResult<SelfTestReport>;
}

/// No-std version of trait (synchronous)
#[cfg(not(feature = "std"))]
pub trait SecureElement {
    /// Initialize the hardware
    fn initialize(&mut self) -> HardwareResult<()>;

    /// Get hardware information
    fn get_info(&self) -> HardwareResult<SecureElementInfo>;

    /// Generate cryptographically secure random bytes
    fn random_bytes(&self, buffer: &mut [u8]) -> HardwareResult<()>;

    /// Store secret share securely
    fn store_share(&mut self, share_id: &str, share: &SecretShare) -> HardwareResult<()>;

    /// Load secret share
    fn load_share(&self, share_id: &str) -> HardwareResult<SecretShare>;

    /// Delete secret share (with secure erasure)
    fn delete_share(&mut self, share_id: &str) -> HardwareResult<()>;

    /// Get hardware attestation
    fn get_attestation(&self) -> HardwareResult<Attestation>;

    /// Perform self-test
    fn self_test(&self) -> HardwareResult<SelfTestReport>;
}

/// Hardware attestation proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Hardware identity public key
    pub identity_key: Vec<u8>,
    /// Attestation signature
    pub signature: Vec<u8>,
    /// Attestation data (nonce, measurements, etc.)
    pub data: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// Self-test report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestReport {
    /// Test passed
    pub passed: bool,
    /// TRNG test
    pub trng_ok: bool,
    /// Crypto operations test
    pub crypto_ok: bool,
    /// Memory test
    pub memory_ok: bool,
    /// Tamper detection test
    pub tamper_ok: bool,
    /// Error details if failed
    pub errors: Vec<String>,
}

/// Secure storage backend
pub trait SecureStorage {
    /// Write encrypted data
    fn write(&mut self, key: &str, data: &[u8]) -> HardwareResult<()>;

    /// Read encrypted data
    fn read(&self, key: &str) -> HardwareResult<Vec<u8>>;

    /// Delete data
    fn delete(&mut self, key: &str) -> HardwareResult<()>;

    /// List all keys
    fn list_keys(&self) -> HardwareResult<Vec<String>>;
}
