//! Hardware Abstraction Layer for FROST RoT
//!
//! Provides unified interface for different secure element implementations:
//! - GigaDevice GD32 (ARM Cortex-M + TrustZone)
//! - Nations Technologies secure elements
//! - Feitian HSM modules
//! - Allwinner/T-Head RISC-V

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

pub mod traits;
pub mod gigadevice;
pub mod nations;
pub mod feitian;
pub mod memory;

pub use traits::*;

use thiserror::Error;

/// Hardware abstraction errors
#[derive(Error, Debug)]
pub enum HardwareError {
    /// Hardware communication error
    #[error("Hardware communication error: {0}")]
    CommunicationError(String),

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// Secure storage error
    #[error("Secure storage error: {0}")]
    StorageError(String),

    /// Hardware not initialized
    #[error("Hardware not initialized")]
    NotInitialized,

    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Attestation failed
    #[error("Attestation failed")]
    AttestationFailed,

    /// Hardware fault detected
    #[error("Hardware fault detected: {0}")]
    HardwareFault(String),
}

/// Result type for hardware operations
pub type HardwareResult<T> = Result<T, HardwareError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_errors() {
        let err = HardwareError::NotInitialized;
        assert_eq!(err.to_string(), "Hardware not initialized");
    }
}
