//! Session Token System for Offline Operation
//!
//! Pre-signed tokens allow offline device operation while maintaining security.
//! Tokens are signed by the full FROST threshold (2-of-3) when online,
//! then cached locally for offline use.

use crate::types::*;
use crate::{FrostError, FrostResult};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::time::{SystemTime, UNIX_EPOCH, Duration};

/// Session token capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    /// Token ID (random)
    pub token_id: [u8; 16],

    /// Issuance timestamp (Unix epoch seconds)
    pub issued_at: u64,

    /// Expiration timestamp (Unix epoch seconds)
    pub expires_at: u64,

    /// Device this token is bound to
    pub device_id: [u8; 32],

    /// Allowed capabilities
    pub capabilities: Capabilities,

    /// Usage tracking
    pub usage: UsageTracker,

    /// FROST signature (2-of-3 threshold)
    pub frost_signature: SchnorrSignature,

    /// Ephemeral signing key (for token operations)
    #[serde(skip)]
    ephemeral_key: Option<SecretScalar>,
}

/// Capabilities granted by this token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    /// Device unlock allowed
    pub device_unlock: bool,

    /// Keychain access level
    pub keychain_access: KeychainAccessLevel,

    /// Payment authorization limits
    pub payment_limits: Option<PaymentLimits>,

    /// Code signing (usually disabled for tokens)
    pub code_signing: bool,

    /// FileVault decryption
    pub filevault_decrypt: bool,

    /// Custom capability flags
    pub custom: Vec<String>,
}

/// Keychain access levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeychainAccessLevel {
    /// No keychain access
    None,
    /// Low-security items only (websites, etc.)
    LowSecurity,
    /// Medium-security items
    MediumSecurity,
    /// All items (requires fresh FROST sig)
    HighSecurity,
}

/// Payment authorization limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentLimits {
    /// Maximum per transaction (cents)
    pub max_per_transaction: u64,

    /// Maximum per day (cents)
    pub max_per_day: u64,

    /// Amount remaining today (cents)
    pub remaining_today: u64,

    /// Daily limit reset time
    pub daily_reset_at: u64,
}

/// Usage tracking for token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageTracker {
    /// Number of times used
    pub use_count: u64,

    /// Last used timestamp
    pub last_used_at: Option<u64>,

    /// Operations performed
    pub operations: Vec<TokenOperation>,
}

/// Record of token operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenOperation {
    /// Operation type
    pub operation: String,

    /// Timestamp
    pub timestamp: u64,

    /// Success/failure
    pub success: bool,
}

impl SessionToken {
    /// Create a new session token (requires FROST signing)
    pub fn new(
        device_id: [u8; 32],
        capabilities: Capabilities,
        lifetime: Duration,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut token_id = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut token_id);

        SessionToken {
            token_id,
            issued_at: now,
            expires_at: now + lifetime.as_secs(),
            device_id,
            capabilities,
            usage: UsageTracker {
                use_count: 0,
                last_used_at: None,
                operations: Vec::new(),
            },
            frost_signature: SchnorrSignature {
                z: [0u8; 32],  // Will be filled by FROST signing
                commitment: CompressedRistretto::default(),
            },
            ephemeral_key: None,
        }
    }

    /// Check if token is valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now >= self.issued_at && now < self.expires_at
    }

    /// Time until expiration
    pub fn time_until_expiry(&self) -> Option<Duration> {
        if !self.is_valid() {
            return None;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Some(Duration::from_secs(self.expires_at - now))
    }

    /// Check if token allows an operation
    pub fn allows_operation(&self, operation: &TokenRequest) -> bool {
        if !self.is_valid() {
            return false;
        }

        match operation {
            TokenRequest::DeviceUnlock => {
                self.capabilities.device_unlock
            }

            TokenRequest::KeychainAccess { level } => {
                match (self.capabilities.keychain_access, level) {
                    (KeychainAccessLevel::None, _) => false,
                    (KeychainAccessLevel::LowSecurity, KeychainAccessLevel::LowSecurity) => true,
                    (KeychainAccessLevel::MediumSecurity, KeychainAccessLevel::LowSecurity) => true,
                    (KeychainAccessLevel::MediumSecurity, KeychainAccessLevel::MediumSecurity) => true,
                    (KeychainAccessLevel::HighSecurity, _) => true,
                    _ => false,
                }
            }

            TokenRequest::Payment { amount } => {
                if let Some(limits) = &self.capabilities.payment_limits {
                    *amount <= limits.max_per_transaction
                        && *amount <= limits.remaining_today
                } else {
                    false
                }
            }

            TokenRequest::CodeSigning => {
                self.capabilities.code_signing
            }

            TokenRequest::FileVaultDecrypt => {
                self.capabilities.filevault_decrypt
            }
        }
    }

    /// Use token for an operation
    pub fn use_for_operation(&mut self, operation: TokenRequest) -> FrostResult<TokenSignature> {
        if !self.allows_operation(&operation) {
            return Err(FrostError::CryptoError("Token does not allow operation".to_string()));
        }

        // Update usage tracking
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.usage.use_count += 1;
        self.usage.last_used_at = Some(now);

        // Update payment limits if applicable
        if let TokenRequest::Payment { amount } = operation {
            if let Some(limits) = &mut self.capabilities.payment_limits {
                limits.remaining_today = limits.remaining_today.saturating_sub(amount);
            }
        }

        // Record operation
        self.usage.operations.push(TokenOperation {
            operation: format!("{:?}", operation),
            timestamp: now,
            success: true,
        });

        // Sign with ephemeral key (in real impl)
        Ok(TokenSignature {
            token_id: self.token_id,
            operation_hash: [0u8; 32],  // Hash of operation
            signature: [0u8; 64],        // Signature with ephemeral key
        })
    }

    /// Verify FROST signature on token
    pub fn verify_frost_signature(&self, public_key: &GroupPublicKey) -> bool {
        // Serialize token data
        let token_data = self.to_signing_data();

        // Verify FROST signature
        public_key.verify_signature(&token_data, &self.frost_signature)
    }

    /// Get token data for signing
    fn to_signing_data(&self) -> Vec<u8> {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(b"FROST-SESSION-TOKEN-v1");
        hasher.update(&self.token_id);
        hasher.update(&self.issued_at.to_le_bytes());
        hasher.update(&self.expires_at.to_le_bytes());
        hasher.update(&self.device_id);

        hasher.finalize().to_vec()
    }
}

/// Request to use a token
#[derive(Debug, Clone)]
pub enum TokenRequest {
    DeviceUnlock,
    KeychainAccess { level: KeychainAccessLevel },
    Payment { amount: u64 },
    CodeSigning,
    FileVaultDecrypt,
}

/// Token signature result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSignature {
    pub token_id: [u8; 16],
    pub operation_hash: [u8; 32],
    pub signature: [u8; 64],
}

/// Session token cache
pub struct SessionTokenCache {
    tokens: Vec<SessionToken>,
    max_tokens: usize,
}

impl SessionTokenCache {
    /// Create new token cache
    pub fn new(max_tokens: usize) -> Self {
        SessionTokenCache {
            tokens: Vec::new(),
            max_tokens,
        }
    }

    /// Add a token to cache
    pub fn add_token(&mut self, token: SessionToken) -> FrostResult<()> {
        // Remove expired tokens
        self.cleanup_expired();

        // Check cache size
        if self.tokens.len() >= self.max_tokens {
            // Remove oldest token
            if let Some(oldest_idx) = self.find_oldest_token() {
                self.tokens.remove(oldest_idx);
            }
        }

        self.tokens.push(token);
        Ok(())
    }

    /// Get a valid token for an operation
    pub fn get_valid_token(&mut self, operation: &TokenRequest) -> Option<&mut SessionToken> {
        self.cleanup_expired();

        self.tokens.iter_mut()
            .filter(|t| t.is_valid() && t.allows_operation(operation))
            .max_by_key(|t| t.expires_at)  // Get longest-lived token
    }

    /// Remove expired tokens
    fn cleanup_expired(&mut self) {
        self.tokens.retain(|t| t.is_valid());
    }

    /// Find oldest token index
    fn find_oldest_token(&self) -> Option<usize> {
        self.tokens.iter()
            .enumerate()
            .min_by_key(|(_, t)| t.issued_at)
            .map(|(idx, _)| idx)
    }

    /// Get token count
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    /// Check if refresh is needed
    pub fn needs_refresh(&self) -> bool {
        // Refresh if we have fewer than 5 tokens or they're expiring soon
        if self.tokens.len() < 5 {
            return true;
        }

        let hour_from_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600;

        // Refresh if any token expires within an hour
        self.tokens.iter()
            .any(|t| t.expires_at < hour_from_now)
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Capabilities {
            device_unlock: true,
            keychain_access: KeychainAccessLevel::LowSecurity,
            payment_limits: Some(PaymentLimits {
                max_per_transaction: 10_000,  // $100
                max_per_day: 50_000,           // $500
                remaining_today: 50_000,
                daily_reset_at: 0,
            }),
            code_signing: false,
            filevault_decrypt: true,
            custom: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_session_token_creation() {
        let device_id = [1u8; 32];
        let caps = Capabilities::default();
        let token = SessionToken::new(device_id, caps, Duration::from_secs(3600));

        assert!(token.is_valid());
        assert!(token.time_until_expiry().is_some());
        assert_eq!(token.usage.use_count, 0);
    }

    #[test]
    fn test_token_capabilities() {
        let device_id = [1u8; 32];
        let caps = Capabilities::default();
        let token = SessionToken::new(device_id, caps, Duration::from_secs(3600));

        assert!(token.allows_operation(&TokenRequest::DeviceUnlock));
        assert!(token.allows_operation(&TokenRequest::Payment { amount: 5000 }));
        assert!(!token.allows_operation(&TokenRequest::Payment { amount: 100_000 }));
        assert!(!token.allows_operation(&TokenRequest::CodeSigning));
    }

    #[test]
    fn test_token_cache() {
        let mut cache = SessionTokenCache::new(10);

        let device_id = [1u8; 32];
        let caps = Capabilities::default();

        for _ in 0..5 {
            let token = SessionToken::new(device_id, caps.clone(), Duration::from_secs(3600));
            cache.add_token(token).unwrap();
        }

        assert_eq!(cache.token_count(), 5);

        let token = cache.get_valid_token(&TokenRequest::DeviceUnlock);
        assert!(token.is_some());
    }

    #[test]
    fn test_payment_limits() {
        let device_id = [1u8; 32];
        let caps = Capabilities::default();
        let mut token = SessionToken::new(device_id, caps, Duration::from_secs(3600));

        // First payment should succeed
        assert!(token.allows_operation(&TokenRequest::Payment { amount: 5000 }));
        let _ = token.use_for_operation(TokenRequest::Payment { amount: 5000 });

        // Check remaining balance decreased
        if let Some(limits) = &token.capabilities.payment_limits {
            assert_eq!(limits.remaining_today, 45_000);
        }
    }
}
