//! GigaDevice GD32 Secure Element Implementation
//!
//! GigaDevice GD32 MCUs with ARM Cortex-M and TrustZone support
//! Common models: GD32W515, GD32E507
//!
//! Manufacturing: Shenzhen, China
//! Features: ARM TrustZone-M, TRNG, AES/DES, RSA/ECC, Secure boot

use crate::{HardwareError, HardwareResult, SecureElementInfo, SecureElementFeatures};
use crate::traits::{SecureElement, Attestation, SelfTestReport};
use frost_core::{SecretShare, ParticipantId, SigningCommitment, PartialSignature};
use zeroize::Zeroizing;

#[cfg(feature = "std")]
use async_trait::async_trait;

/// GigaDevice GD32 secure element
pub struct GigaDeviceGD32 {
    initialized: bool,
    /// Simulated secure storage (in real HW, this is TrustZone secure memory)
    secure_storage: std::collections::HashMap<String, Vec<u8>>,
}

impl GigaDeviceGD32 {
    /// Create new GD32 instance
    pub fn new() -> Self {
        GigaDeviceGD32 {
            initialized: false,
            secure_storage: std::collections::HashMap::new(),
        }
    }

    /// Hardware-specific: Access TrustZone secure world
    #[cfg(feature = "gigadevice-gd32")]
    fn enter_secure_world(&self) -> HardwareResult<()> {
        // In real hardware, this would:
        // 1. Trigger SG (Secure Gateway) instruction
        // 2. Switch to Secure state
        // 3. Verify MPU/SAU configuration
        Ok(())
    }

    /// Hardware-specific: Use hardware TRNG
    fn hw_random_bytes(&self, buffer: &mut [u8]) -> HardwareResult<()> {
        // In real hardware:
        // - Access RNG peripheral at 0x40023C00
        // - Check RNG_SR for DRDY bit
        // - Read from RNG_DR register
        // - Perform NIST SP 800-90B health tests

        // Simulation: use system RNG
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buffer);
        Ok(())
    }

    /// Hardware-specific: Use ECC accelerator
    fn hw_ecc_point_multiply(&self, scalar: &[u8], point: &[u8]) -> HardwareResult<Vec<u8>> {
        // In real hardware:
        // - Program PKA (Public Key Accelerator) registers
        // - Start operation via PKA_CR
        // - Poll PKA_SR for completion
        // - Read result from PKA memory

        // Simulation: return placeholder
        Ok(vec![0u8; 64])
    }
}

impl Default for GigaDeviceGD32 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
#[async_trait]
impl SecureElement for GigaDeviceGD32 {
    async fn initialize(&mut self) -> HardwareResult<()> {
        // Real hardware initialization:
        // 1. Enable TrustZone MPU/SAU
        // 2. Configure secure/non-secure memory regions
        // 3. Initialize TRNG peripheral
        // 4. Verify secure boot chain
        // 5. Initialize ECC accelerator

        self.initialized = true;
        log::info!("GigaDevice GD32 initialized");
        Ok(())
    }

    async fn get_info(&self) -> HardwareResult<SecureElementInfo> {
        Ok(SecureElementInfo {
            manufacturer: "GigaDevice".to_string(),
            model: "GD32W515".to_string(),
            firmware_version: "1.0.0".to_string(),
            serial_number: [0x47, 0x44, 0x33, 0x32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            features: SecureElementFeatures {
                has_trng: true,
                has_aes: true,
                has_ecc: true,
                has_secure_boot: true,
                has_trustzone: true,
                has_puf: false,
                has_tamper_detection: true,
            },
        })
    }

    async fn random_bytes(&self, buffer: &mut [u8]) -> HardwareResult<()> {
        if !self.initialized {
            return Err(HardwareError::NotInitialized);
        }
        self.hw_random_bytes(buffer)
    }

    async fn store_share(&mut self, share_id: &str, share: &SecretShare) -> HardwareResult<()> {
        if !self.initialized {
            return Err(HardwareError::NotInitialized);
        }

        // Serialize share
        let serialized = bincode::serialize(share)
            .map_err(|e| HardwareError::StorageError(e.to_string()))?;

        // In real hardware: store in TrustZone secure SRAM
        // Encrypt with hardware key from PUF or OTP
        self.secure_storage.insert(share_id.to_string(), serialized);

        log::info!("Stored share {} in secure storage", share_id);
        Ok(())
    }

    async fn load_share(&self, share_id: &str) -> HardwareResult<SecretShare> {
        if !self.initialized {
            return Err(HardwareError::NotInitialized);
        }

        let data = self.secure_storage
            .get(share_id)
            .ok_or_else(|| HardwareError::StorageError("Share not found".to_string()))?;

        let share = bincode::deserialize(data)
            .map_err(|e| HardwareError::StorageError(e.to_string()))?;

        Ok(share)
    }

    async fn delete_share(&mut self, share_id: &str) -> HardwareResult<()> {
        if !self.initialized {
            return Err(HardwareError::NotInitialized);
        }

        // In real hardware: overwrite memory multiple times before deletion
        if let Some(mut data) = self.secure_storage.remove(share_id) {
            use zeroize::Zeroize;
            data.zeroize();
        }

        log::info!("Deleted share {} from secure storage", share_id);
        Ok(())
    }

    async fn signing_round1(
        &self,
        share_id: &str,
        session_id: &[u8],
    ) -> HardwareResult<SigningCommitment> {
        // Real implementation would:
        // 1. Load share from secure storage
        // 2. Generate nonces using TRNG
        // 3. Compute commitments using ECC accelerator
        // 4. Return commitment (no secrets leaked)

        Err(HardwareError::CryptoError("Not implemented in simulation".to_string()))
    }

    async fn signing_round2(
        &self,
        share_id: &str,
        session_id: &[u8],
        message: &[u8],
        commitments: &[SigningCommitment],
    ) -> HardwareResult<PartialSignature> {
        // Real implementation would:
        // 1. Load share and Round 1 nonces
        // 2. Verify all commitments
        // 3. Compute partial signature using ECC accelerator
        // 4. Zeroize nonces
        // 5. Return partial signature

        Err(HardwareError::CryptoError("Not implemented in simulation".to_string()))
    }

    async fn get_attestation(&self) -> HardwareResult<Attestation> {
        // Real implementation:
        // 1. Read device unique ID from OTP
        // 2. Generate attestation key (derived from PUF or OTP)
        // 3. Sign measurement data (firmware hash, config, etc.)
        // 4. Return attestation bundle

        Ok(Attestation {
            identity_key: vec![0u8; 32],
            signature: vec![0u8; 64],
            data: vec![],
            timestamp: 0,
        })
    }

    async fn self_test(&self) -> HardwareResult<SelfTestReport> {
        // Real implementation performs:
        // 1. TRNG statistical tests (NIST SP 800-90B)
        // 2. Crypto operation known-answer tests
        // 3. Memory integrity check (ECC, parity)
        // 4. Tamper sensor check

        Ok(SelfTestReport {
            passed: true,
            trng_ok: true,
            crypto_ok: true,
            memory_ok: true,
            tamper_ok: true,
            errors: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gd32_init() {
        let mut se = GigaDeviceGD32::new();
        assert!(se.initialize().await.is_ok());

        let info = se.get_info().await.unwrap();
        assert_eq!(info.manufacturer, "GigaDevice");
        assert!(info.features.has_trustzone);
    }

    #[tokio::test]
    async fn test_gd32_random() {
        let mut se = GigaDeviceGD32::new();
        se.initialize().await.unwrap();

        let mut buffer = [0u8; 32];
        assert!(se.random_bytes(&mut buffer).await.is_ok());

        // Verify not all zeros
        assert_ne!(buffer, [0u8; 32]);
    }
}
