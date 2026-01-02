//! Hybrid FROST Implementation
//!
//! Combines local share with remote shares for offline capability.
//! Architecture: 1 local share + 2 remote shares (2-of-3 threshold)

use crate::types::*;
use crate::signing::*;
use crate::session_token::*;
use crate::{FrostError, FrostResult};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Hybrid FROST signing modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningMode {
    /// Full distributed (all 3 shares remote) - best security
    FullDistributed,

    /// Hybrid (1 local + 1 remote = threshold) - balanced
    Hybrid,

    /// Session token (offline with pre-signed token) - good security
    SessionToken,

    /// Degraded local-only (emergency offline) - reduced security
    DegradedLocal,
}

/// Hybrid FROST device
pub struct HybridFROSTDevice {
    /// Local share (encrypted to PUF)
    local_share: Option<SecretShare>,

    /// Group public key
    group_public_key: GroupPublicKey,

    /// Session token cache
    token_cache: SessionTokenCache,

    /// Remote share endpoints
    remote_shares: Vec<RemoteShareEndpoint>,

    /// Preferred signing mode
    preferred_mode: SigningMode,

    /// Allow degraded mode
    allow_degraded: bool,
}

/// Remote share endpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteShareEndpoint {
    /// Share participant ID
    pub participant_id: ParticipantId,

    /// Location description
    pub location: String,

    /// Operator name
    pub operator: String,

    /// HTTPS endpoint URL
    pub endpoint_url: String,

    /// TLS certificate fingerprint
    pub cert_fingerprint: [u8; 32],

    /// Currently available
    pub available: bool,

    /// Average response time (ms)
    pub avg_response_time: u64,
}

impl HybridFROSTDevice {
    /// Create new hybrid device
    pub fn new(
        local_share: Option<SecretShare>,
        group_public_key: GroupPublicKey,
        remote_shares: Vec<RemoteShareEndpoint>,
    ) -> Self {
        HybridFROSTDevice {
            local_share,
            group_public_key,
            token_cache: SessionTokenCache::new(20),
            remote_shares,
            preferred_mode: SigningMode::Hybrid,
            allow_degraded: false,
        }
    }

    /// Sign a message using best available method
    pub async fn sign(&mut self, message: &[u8]) -> FrostResult<SchnorrSignature> {
        // Try each mode in order of security

        // Mode 1: Hybrid (local + 1 remote)
        if matches!(self.preferred_mode, SigningMode::Hybrid) {
            if let Some(_local) = &self.local_share {
                if let Ok(sig) = self.hybrid_sign(message).await {
                    return Ok(sig);
                }
            }
        }

        // Mode 2: Session token
        if let Some(token) = self.token_cache.get_valid_token(&TokenRequest::DeviceUnlock) {
            if let Ok(token_sig) = token.use_for_operation(TokenRequest::DeviceUnlock) {
                // Convert token signature to Schnorr signature
                // (In real impl, token has its own key)
                return self.token_to_signature(token_sig);
            }
        }

        // Mode 3: Degraded local-only (requires user consent)
        if self.allow_degraded {
            if let Some(local) = &self.local_share {
                log::warn!("Using degraded local-only signing mode");
                return self.local_only_sign(message, local);
            }
        }

        Err(FrostError::CryptoError("No valid signing path available".to_string()))
    }

    /// Hybrid signing: local share + 1 remote
    async fn hybrid_sign(&self, message: &[u8]) -> FrostResult<SchnorrSignature> {
        let local_share = self.local_share.as_ref()
            .ok_or(FrostError::CryptoError("No local share".to_string()))?;

        // Find best available remote share
        let remote = self.remote_shares.iter()
            .find(|r| r.available)
            .ok_or(FrostError::CryptoError("No remote shares available".to_string()))?;

        // Start Round 1 locally
        let mut rng = rand::thread_rng();
        let local_round1 = SigningRound1::new(
            local_share.participant_id,
            local_share,
            &mut rng,
        );

        let local_commitment = local_round1.commitment();

        // Request commitment from remote share
        let remote_commitment = self.request_remote_commitment(remote, message).await?;

        let commitments = vec![local_commitment.clone(), remote_commitment];

        // Proceed to Round 2
        let local_round2 = local_round1.into_round2(message, &commitments)?;
        let local_partial = local_round2.partial_signature();

        // Get remote partial signature
        let remote_partial = self.request_remote_partial(
            remote,
            message,
            &commitments,
        ).await?;

        // Aggregate signatures
        let group_commitment = local_round2.group_commitment();
        let signature = aggregate_signatures(
            message,
            &group_commitment,
            &[local_partial, remote_partial],
        )?;

        // Verify
        if !self.group_public_key.verify_signature(message, &signature) {
            return Err(FrostError::CryptoError("Signature verification failed".to_string()));
        }

        Ok(signature)
    }

    /// Request commitment from remote share (async network call)
    async fn request_remote_commitment(
        &self,
        remote: &RemoteShareEndpoint,
        message: &[u8],
    ) -> FrostResult<SigningCommitment> {
        // In real implementation:
        // 1. Make HTTPS request to remote.endpoint_url
        // 2. Send message hash + session ID
        // 3. Verify TLS cert matches remote.cert_fingerprint
        // 4. Receive commitment
        // 5. Verify attestation

        // Placeholder for simulation
        log::info!("Requesting commitment from {} ({})", remote.operator, remote.location);

        Err(FrostError::CryptoError("Network simulation not implemented".to_string()))
    }

    /// Request partial signature from remote share
    async fn request_remote_partial(
        &self,
        remote: &RemoteShareEndpoint,
        message: &[u8],
        commitments: &[SigningCommitment],
    ) -> FrostResult<PartialSignature> {
        // Similar to request_remote_commitment
        log::info!("Requesting partial signature from {}", remote.operator);

        Err(FrostError::CryptoError("Network simulation not implemented".to_string()))
    }

    /// Local-only signing (degraded mode)
    fn local_only_sign(
        &self,
        message: &[u8],
        local_share: &SecretShare,
    ) -> FrostResult<SchnorrSignature> {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::scalar::Scalar;
        use sha2::{Sha512, Digest};

        // Single-share signing (NOT threshold!)
        // This is less secure but allows offline operation

        let mut rng = rand::thread_rng();
        let nonce = Scalar::random(&mut rng);
        let r = nonce * RISTRETTO_BASEPOINT_POINT;

        // Compute challenge
        let mut hasher = Sha512::new();
        hasher.update(b"FROST-DEGRADED-v1");
        hasher.update(r.compress().as_bytes());
        hasher.update(message);
        let challenge = Scalar::from_hash(hasher);

        // Compute signature z = nonce + challenge * secret
        let z = nonce + challenge * local_share.value.as_scalar();

        let signature = SchnorrSignature {
            z: z.to_bytes(),
            commitment: r.compress(),
        };

        Ok(signature)
    }

    /// Convert token signature to Schnorr signature
    fn token_to_signature(&self, token_sig: TokenSignature) -> FrostResult<SchnorrSignature> {
        // In real implementation, token has its own ephemeral key
        // and can produce valid signatures

        use curve25519_dalek::ristretto::CompressedRistretto;

        let mut z = [0u8; 32];
        z.copy_from_slice(&token_sig.signature[..32]);

        Ok(SchnorrSignature {
            z,
            commitment: CompressedRistretto::default(),
        })
    }

    /// Refresh session tokens (call when online)
    pub async fn refresh_tokens(&mut self) -> FrostResult<()> {
        if !self.token_cache.needs_refresh() {
            return Ok(());
        }

        // Generate new session token
        let device_id = [0u8; 32];  // Get from hardware
        let capabilities = Capabilities::default();
        let lifetime = std::time::Duration::from_secs(4 * 3600);  // 4 hours

        let mut token = SessionToken::new(device_id, capabilities, lifetime);

        // Sign token with full FROST (requires network)
        let token_data = token.to_signing_data();
        let signature = self.sign(&token_data).await?;
        token.frost_signature = signature;

        // Add to cache
        self.token_cache.add_token(token)?;

        log::info!("Refreshed session token cache ({} tokens)", self.token_cache.token_count());

        Ok(())
    }

    /// Enable/disable degraded mode
    pub fn set_allow_degraded(&mut self, allow: bool) {
        self.allow_degraded = allow;
    }

    /// Get current signing mode capability
    pub fn get_current_mode(&self) -> SigningMode {
        // Check what's currently available
        if self.local_share.is_some() && self.remote_shares.iter().any(|r| r.available) {
            return SigningMode::Hybrid;
        }

        if let Some(_token) = self.token_cache.get_valid_token(&TokenRequest::DeviceUnlock) {
            return SigningMode::SessionToken;
        }

        if self.allow_degraded && self.local_share.is_some() {
            return SigningMode::DegradedLocal;
        }

        SigningMode::FullDistributed  // Default/unavailable
    }
}

/// Signing mode info for display
impl SigningMode {
    /// Get security level (1-5 stars)
    pub fn security_level(&self) -> u8 {
        match self {
            SigningMode::FullDistributed => 5,
            SigningMode::Hybrid => 4,
            SigningMode::SessionToken => 4,
            SigningMode::DegradedLocal => 2,
        }
    }

    /// Get typical latency (ms)
    pub fn typical_latency_ms(&self) -> u64 {
        match self {
            SigningMode::FullDistributed => 500,
            SigningMode::Hybrid => 350,
            SigningMode::SessionToken => 50,
            SigningMode::DegradedLocal => 50,
        }
    }

    /// User-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            SigningMode::FullDistributed => "Full FROST (2-of-3 remote shares)",
            SigningMode::Hybrid => "Hybrid (1 local + 1 remote share)",
            SigningMode::SessionToken => "Offline with pre-signed token",
            SigningMode::DegradedLocal => "⚠️  Local-only (reduced security)",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::DkgCoordinator;
    use rand::rngs::OsRng;

    #[test]
    fn test_signing_mode_security() {
        assert_eq!(SigningMode::FullDistributed.security_level(), 5);
        assert_eq!(SigningMode::Hybrid.security_level(), 4);
        assert_eq!(SigningMode::SessionToken.security_level(), 4);
        assert_eq!(SigningMode::DegradedLocal.security_level(), 2);
    }

    #[test]
    fn test_hybrid_device_creation() {
        let mut rng = OsRng;

        // Run DKG to get shares
        let coordinator = DkgCoordinator::new(2, 3).unwrap();
        let dkg_outputs = coordinator.run_dkg(&mut rng).unwrap();

        let local_share = dkg_outputs[0].secret_share.clone();
        let group_pk = dkg_outputs[0].group_public_key.clone();

        let remote_shares = vec![
            RemoteShareEndpoint {
                participant_id: ParticipantId::new(2).unwrap(),
                location: "Zürich, CH".to_string(),
                operator: "Securosys".to_string(),
                endpoint_url: "https://frost.securosys.ch:8443".to_string(),
                cert_fingerprint: [0u8; 32],
                available: true,
                avg_response_time: 200,
            },
        ];

        let device = HybridFROSTDevice::new(
            Some(local_share),
            group_pk,
            remote_shares,
        );

        assert_eq!(device.get_current_mode(), SigningMode::Hybrid);
    }
}
