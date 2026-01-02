//! Cryptographic transcripts for DKG and rotation ceremonies
//!
//! Provides tamper-evident logging of all protocol messages

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

/// Transcript of a DKG ceremony
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgTranscript {
    /// Protocol version
    pub version: u32,
    /// Timestamp (Unix epoch)
    pub timestamp: u64,
    /// Threshold
    pub threshold: u32,
    /// Number of participants
    pub num_participants: u32,
    /// Round 1 broadcasts
    pub round1_broadcasts: Vec<serde_json::Value>,
    /// Hash of complete transcript
    pub transcript_hash: [u8; 32],
}

impl DkgTranscript {
    /// Create new transcript
    pub fn new(
        timestamp: u64,
        threshold: u32,
        num_participants: u32,
        round1_broadcasts: Vec<serde_json::Value>,
    ) -> Self {
        let mut transcript = DkgTranscript {
            version: 1,
            timestamp,
            threshold,
            num_participants,
            round1_broadcasts,
            transcript_hash: [0u8; 32],
        };

        // Compute hash
        transcript.transcript_hash = transcript.compute_hash();
        transcript
    }

    /// Compute hash of transcript
    fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"FROST-DKG-TRANSCRIPT-v1");
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.threshold.to_le_bytes());
        hasher.update(&self.num_participants.to_le_bytes());

        // Hash each broadcast
        for broadcast in &self.round1_broadcasts {
            if let Ok(json) = serde_json::to_vec(broadcast) {
                hasher.update(&json);
            }
        }

        hasher.finalize().into()
    }

    /// Verify transcript integrity
    pub fn verify(&self) -> bool {
        self.transcript_hash == self.compute_hash()
    }
}

/// Transcript of a share rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationTranscript {
    /// Protocol version
    pub version: u32,
    /// Timestamp (Unix epoch)
    pub timestamp: u64,
    /// Previous DKG or rotation transcript hash
    pub previous_hash: [u8; 32],
    /// Rotation commitments
    pub commitments: Vec<serde_json::Value>,
    /// Hash of complete transcript
    pub transcript_hash: [u8; 32],
}

impl RotationTranscript {
    /// Create new rotation transcript
    pub fn new(
        timestamp: u64,
        previous_hash: [u8; 32],
        commitments: Vec<serde_json::Value>,
    ) -> Self {
        let mut transcript = RotationTranscript {
            version: 1,
            timestamp,
            previous_hash,
            commitments,
            transcript_hash: [0u8; 32],
        };

        transcript.transcript_hash = transcript.compute_hash();
        transcript
    }

    fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"FROST-ROTATION-TRANSCRIPT-v1");
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.previous_hash);

        for commitment in &self.commitments {
            if let Ok(json) = serde_json::to_vec(commitment) {
                hasher.update(&json);
            }
        }

        hasher.finalize().into()
    }

    /// Verify transcript integrity
    pub fn verify(&self) -> bool {
        self.transcript_hash == self.compute_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkg_transcript() {
        let transcript = DkgTranscript::new(
            1704196800,
            2,
            3,
            vec![],
        );

        assert!(transcript.verify());
    }

    #[test]
    fn test_rotation_transcript() {
        let transcript = RotationTranscript::new(
            1704196800,
            [0u8; 32],
            vec![],
        );

        assert!(transcript.verify());
    }
}
