//! FROST Two-Round Signing Protocol
//!
//! Round 1: Each signer commits to nonce
//! Round 2: Each signer computes partial signature
//! Aggregation: Coordinator combines partial signatures into final signature

use crate::types::*;
use crate::{FrostError, FrostResult};
use curve25519_dalek::{
    ristretto::{RistrettoPoint, CompressedRistretto},
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
};
use rand_core::{RngCore, CryptoRng};
use serde::{Serialize, Deserialize};
use sha2::{Sha512, Digest};
use std::collections::{HashMap, HashSet};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Signer state for Round 1
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningRound1 {
    /// My participant ID
    #[zeroize(skip)]
    participant_id: ParticipantId,
    /// My secret share
    secret_share: SecretScalar,
    /// Hiding nonce d_i
    hiding_nonce: SecretScalar,
    /// Binding nonce e_i
    binding_nonce: SecretScalar,
    /// Hiding nonce commitment D_i = d_i * G
    #[zeroize(skip)]
    hiding_commitment: RistrettoPoint,
    /// Binding nonce commitment E_i = e_i * G
    #[zeroize(skip)]
    binding_commitment: RistrettoPoint,
}

impl SigningRound1 {
    /// Initialize signing round 1
    pub fn new<R: RngCore + CryptoRng>(
        participant_id: ParticipantId,
        secret_share: &SecretShare,
        rng: &mut R,
    ) -> Self {
        let hiding_nonce = SecretScalar::new(Scalar::random(rng));
        let binding_nonce = SecretScalar::new(Scalar::random(rng));

        let g = RISTRETTO_BASEPOINT_POINT;
        let hiding_commitment = hiding_nonce.as_scalar() * g;
        let binding_commitment = binding_nonce.as_scalar() * g;

        SigningRound1 {
            participant_id,
            secret_share: secret_share.value.clone(),
            hiding_nonce,
            binding_nonce,
            hiding_commitment,
            binding_commitment,
        }
    }

    /// Generate Round 1 commitment
    pub fn commitment(&self) -> SigningCommitment {
        SigningCommitment {
            participant_id: self.participant_id,
            hiding: self.hiding_commitment.compress(),
            binding: self.binding_commitment.compress(),
        }
    }

    /// Proceed to Round 2
    pub fn into_round2(self, message: &[u8], commitments: &[SigningCommitment]) -> FrostResult<SigningRound2> {
        // Verify we're included in commitments
        if !commitments.iter().any(|c| c.participant_id == self.participant_id) {
            return Err(FrostError::InvalidParticipantIndex(self.participant_id.as_u32()));
        }

        // Compute binding factor for each participant
        let binding_factors = compute_binding_factors(message, commitments);

        // Compute group commitment R
        let group_commitment = compute_group_commitment(commitments, &binding_factors)?;

        // Compute challenge c = H(R || PK || m)
        // Note: In real usage, PK would be passed in
        let challenge = compute_challenge(&group_commitment, message);

        // Compute my binding factor
        let my_binding = binding_factors
            .get(&self.participant_id)
            .ok_or(FrostError::InvalidParticipantIndex(self.participant_id.as_u32()))?;

        // Compute my partial signature
        // z_i = d_i + (e_i * ρ_i) + λ_i * s_i * c
        // where:
        //   - d_i is hiding nonce
        //   - e_i is binding nonce
        //   - ρ_i is binding factor for participant i
        //   - λ_i is Lagrange coefficient
        //   - s_i is secret share
        //   - c is challenge

        let lambda = compute_lagrange_coefficient(
            self.participant_id,
            &commitments.iter().map(|c| c.participant_id).collect::<Vec<_>>(),
        );

        let z = self.hiding_nonce.as_scalar()
            + (self.binding_nonce.as_scalar() * my_binding)
            + (lambda * self.secret_share.as_scalar() * challenge);

        Ok(SigningRound2 {
            participant_id: self.participant_id,
            group_commitment,
            challenge,
            partial_signature: SecretScalar::new(z),
        })
    }
}

/// Commitment sent in Round 1
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningCommitment {
    /// Participant ID
    pub participant_id: ParticipantId,
    /// Hiding commitment D_i
    pub hiding: CompressedRistretto,
    /// Binding commitment E_i
    pub binding: CompressedRistretto,
}

/// Round 2 signer state and partial signature
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningRound2 {
    /// My participant ID
    #[zeroize(skip)]
    participant_id: ParticipantId,
    /// Group commitment R
    #[zeroize(skip)]
    group_commitment: RistrettoPoint,
    /// Challenge c
    #[zeroize(skip)]
    challenge: Scalar,
    /// My partial signature z_i
    partial_signature: SecretScalar,
}

impl SigningRound2 {
    /// Get the partial signature
    pub fn partial_signature(&self) -> PartialSignature {
        PartialSignature {
            participant_id: self.participant_id,
            z: *self.partial_signature.as_scalar(),
        }
    }

    /// Get group commitment
    pub fn group_commitment(&self) -> CompressedRistretto {
        self.group_commitment.compress()
    }
}

/// Partial signature from one participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    /// Participant ID
    pub participant_id: ParticipantId,
    /// Partial signature value z_i
    pub z: Scalar,
}

/// Compute binding factors ρ_i for each participant
fn compute_binding_factors(
    message: &[u8],
    commitments: &[SigningCommitment],
) -> HashMap<ParticipantId, Scalar> {
    let mut factors = HashMap::new();

    for commitment in commitments {
        let mut hasher = Sha512::new();
        hasher.update(b"FROST-RISTRETTO255-SHA512-v1-rho");
        hasher.update(message);
        hasher.update(commitment.participant_id.as_u32().to_le_bytes());
        hasher.update(commitment.hiding.as_bytes());
        hasher.update(commitment.binding.as_bytes());

        factors.insert(commitment.participant_id, Scalar::from_hash(hasher));
    }

    factors
}

/// Compute group commitment R = Π(D_i + ρ_i * E_i)
fn compute_group_commitment(
    commitments: &[SigningCommitment],
    binding_factors: &HashMap<ParticipantId, Scalar>,
) -> FrostResult<RistrettoPoint> {
    let mut group_commitment = RistrettoPoint::identity();

    for commitment in commitments {
        let d = commitment.hiding.decompress()
            .ok_or(FrostError::CryptoError("Invalid hiding commitment".to_string()))?;

        let e = commitment.binding.decompress()
            .ok_or(FrostError::CryptoError("Invalid binding commitment".to_string()))?;

        let rho = binding_factors
            .get(&commitment.participant_id)
            .ok_or(FrostError::InvalidParticipantIndex(commitment.participant_id.as_u32()))?;

        group_commitment += d + (*rho * e);
    }

    Ok(group_commitment)
}

/// Compute challenge c = H(R || PK || m)
fn compute_challenge(group_commitment: &RistrettoPoint, message: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"FROST-RISTRETTO255-SHA512-v1-challenge");
    hasher.update(group_commitment.compress().as_bytes());
    hasher.update(message);

    Scalar::from_hash(hasher)
}

/// Compute Lagrange coefficient λ_i for participant i over the set S
fn compute_lagrange_coefficient(
    participant_id: ParticipantId,
    participants: &[ParticipantId],
) -> Scalar {
    let x_i = participant_id.as_scalar();
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for x_j in participants.iter().map(|p| p.as_scalar()) {
        if x_j == x_i {
            continue;
        }

        numerator *= x_j;
        denominator *= x_j - x_i;
    }

    numerator * denominator.invert()
}

/// Aggregate partial signatures into final signature
pub fn aggregate_signatures(
    message: &[u8],
    group_commitment: &CompressedRistretto,
    partial_signatures: &[PartialSignature],
) -> FrostResult<SchnorrSignature> {
    if partial_signatures.is_empty() {
        return Err(FrostError::InsufficientParticipants(0, 1));
    }

    // Check for duplicates
    let unique_ids: HashSet<_> = partial_signatures.iter()
        .map(|s| s.participant_id)
        .collect();

    if unique_ids.len() != partial_signatures.len() {
        return Err(FrostError::AggregationFailed);
    }

    // Sum all partial signatures
    let mut z = Scalar::ZERO;
    for partial in partial_signatures {
        z += partial.z;
    }

    Ok(SchnorrSignature {
        z: z.to_bytes(),
        commitment: *group_commitment,
    })
}

/// Verify a partial signature (requires verification share)
pub fn verify_partial_signature(
    message: &[u8],
    commitments: &[SigningCommitment],
    partial_sig: &PartialSignature,
    verification_share: &PublicKeyShare,
    group_commitment: &RistrettoPoint,
) -> FrostResult<bool> {
    let g = RISTRETTO_BASEPOINT_POINT;

    // Get commitment for this participant
    let commitment = commitments
        .iter()
        .find(|c| c.participant_id == partial_sig.participant_id)
        .ok_or(FrostError::InvalidParticipantIndex(partial_sig.participant_id.as_u32()))?;

    let d = commitment.hiding.decompress()
        .ok_or(FrostError::CryptoError("Invalid hiding commitment".to_string()))?;

    let e = commitment.binding.decompress()
        .ok_or(FrostError::CryptoError("Invalid binding commitment".to_string()))?;

    let y_i = verification_share.public_key.decompress()
        .ok_or(FrostError::CryptoError("Invalid verification share".to_string()))?;

    // Compute binding factor
    let binding_factors = compute_binding_factors(message, commitments);
    let rho = binding_factors
        .get(&partial_sig.participant_id)
        .ok_or(FrostError::InvalidParticipantIndex(partial_sig.participant_id.as_u32()))?;

    // Compute challenge and Lagrange coefficient
    let challenge = compute_challenge(group_commitment, message);
    let participants: Vec<_> = commitments.iter().map(|c| c.participant_id).collect();
    let lambda = compute_lagrange_coefficient(partial_sig.participant_id, &participants);

    // Verify: z_i * G == D_i + (ρ_i * E_i) + (λ_i * c * Y_i)
    let lhs = partial_sig.z * g;
    let rhs = d + (*rho * e) + (lambda * challenge * y_i);

    Ok(lhs == rhs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::DkgCoordinator;
    use rand::rngs::OsRng;

    #[test]
    fn test_full_signing_protocol() {
        let mut rng = OsRng;

        // Run DKG first
        let coordinator = DkgCoordinator::new(2, 3).unwrap();
        let dkg_outputs = coordinator.run_dkg(&mut rng).unwrap();

        let message = b"Hello, FROST!";

        // All participants start Round 1
        let mut round1_states = Vec::new();
        let mut commitments = Vec::new();

        for output in &dkg_outputs {
            let round1 = SigningRound1::new(
                output.participant_id,
                &output.secret_share,
                &mut rng,
            );
            commitments.push(round1.commitment());
            round1_states.push(round1);
        }

        // All participants move to Round 2 (using only first 2 signers)
        let signing_commitments = commitments[..2].to_vec();
        let mut partial_sigs = Vec::new();
        let mut group_commitment = None;

        for round1 in round1_states.iter().take(2) {
            let round2 = round1.clone().into_round2(message, &signing_commitments).unwrap();
            if group_commitment.is_none() {
                group_commitment = Some(round2.group_commitment());
            }
            partial_sigs.push(round2.partial_signature());
        }

        // Aggregate signatures
        let signature = aggregate_signatures(
            message,
            &group_commitment.unwrap(),
            &partial_sigs,
        ).unwrap();

        // Verify signature
        assert!(dkg_outputs[0].group_public_key.verify_signature(message, &signature));
    }

    #[test]
    fn test_lagrange_coefficient() {
        let p1 = ParticipantId::new(1).unwrap();
        let p2 = ParticipantId::new(2).unwrap();
        let p3 = ParticipantId::new(3).unwrap();

        let participants = vec![p1, p2];

        // λ_1 = 2 / (2-1) = 2
        let lambda1 = compute_lagrange_coefficient(p1, &participants);
        assert_eq!(lambda1, Scalar::from(2u64));

        // λ_2 = -1 / (1-2) = 1
        let lambda2 = compute_lagrange_coefficient(p2, &participants);
        assert_eq!(lambda2, -Scalar::ONE);
    }
}
