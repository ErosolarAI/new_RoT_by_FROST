//! FROST (Flexible Round-Optimized Schnorr Threshold) Core Implementation
//!
//! This crate implements the FROST threshold signature scheme using Ristretto255.
//! Designed for hardware security modules with support for:
//! - Distributed Key Generation (DKG) with Pedersen commitments
//! - Two-round threshold signing
//! - Proactive share rotation
//! - Hardware-friendly operations (no heap allocation in critical paths)

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod dkg;
pub mod signing;
pub mod rotation;
pub mod types;
pub mod transcript;
pub mod session_token;
pub mod hybrid;
pub mod derived_key;

pub use types::*;
pub use dkg::{DkgParticipant, DkgRound1, DkgRound2, DkgOutput};
pub use signing::{SigningRound1, SigningRound2, aggregate_signatures};
pub use rotation::ShareRotation;
pub use session_token::{SessionToken, SessionTokenCache, TokenRequest, Capabilities};
pub use hybrid::{HybridFROSTDevice, SigningMode, RemoteShareEndpoint};
pub use derived_key::{DerivedDeviceKey, DerivationProof, ManufacturingProvisioner};

use thiserror::Error;

/// FROST protocol errors
#[derive(Error, Debug)]
pub enum FrostError {
    /// Invalid participant index
    #[error("Invalid participant index: {0}")]
    InvalidParticipantIndex(u32),

    /// Invalid threshold parameters
    #[error("Invalid threshold: t={0}, n={1} (require 1 <= t <= n)")]
    InvalidThreshold(u32, u32),

    /// Commitment verification failed
    #[error("Commitment verification failed for participant {0}")]
    CommitmentVerificationFailed(u32),

    /// Invalid signature share
    #[error("Invalid signature share from participant {0}")]
    InvalidSignatureShare(u32),

    /// Signature aggregation failed
    #[error("Signature aggregation failed")]
    AggregationFailed,

    /// Insufficient participants for threshold
    #[error("Insufficient participants: got {0}, need {1}")]
    InsufficientParticipants(usize, u32),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}

/// Result type for FROST operations
pub type FrostResult<T> = Result<T, FrostError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_imports() {
        // Ensure all public types are accessible
        let _ = FrostError::InvalidThreshold(2, 3);
    }
}
