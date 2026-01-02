//! Proactive Share Rotation
//!
//! Allows participants to refresh their shares without changing the group public key.
//! This provides forward security: compromise of old shares doesn't help after rotation.

use crate::types::*;
use crate::{FrostError, FrostResult};
use crate::dkg::pedersen_h_generator;
use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
};
use rand_core::{RngCore, CryptoRng};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Share rotation participant
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ShareRotation {
    /// My participant ID
    #[zeroize(skip)]
    my_id: ParticipantId,
    /// Current secret share
    current_share: SecretScalar,
    /// Threshold
    #[zeroize(skip)]
    threshold: u32,
    /// Number of participants
    #[zeroize(skip)]
    num_participants: u32,
    /// Zero-sum polynomial δ(x) where δ(0) = 0
    delta_poly: Polynomial,
}

impl ShareRotation {
    /// Initialize share rotation
    pub fn new<R: RngCore + CryptoRng>(
        my_id: ParticipantId,
        current_share: &SecretShare,
        threshold: u32,
        num_participants: u32,
        rng: &mut R,
    ) -> FrostResult<Self> {
        if threshold == 0 || threshold > num_participants {
            return Err(FrostError::InvalidThreshold(threshold, num_participants));
        }

        // Generate zero-sum polynomial: δ(x) = r_1*x + r_2*x^2 + ... + r_{t-1}*x^{t-1}
        // Note: constant term is 0 to maintain the same secret
        let mut coefficients = vec![SecretScalar::new(Scalar::ZERO)];
        for _ in 0..(threshold - 1) {
            coefficients.push(SecretScalar::new(Scalar::random(rng)));
        }

        Ok(ShareRotation {
            my_id,
            current_share: current_share.value.clone(),
            threshold,
            num_participants,
            delta_poly: Polynomial { coefficients },
        })
    }

    /// Generate commitments to delta polynomial
    pub fn generate_commitments(&self) -> RotationCommitment {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = pedersen_h_generator();

        // For rotation, we only commit to the delta polynomial
        // Blinding is not strictly necessary but we use it for consistency
        let blinding_poly = Polynomial::new(
            vec![Scalar::ZERO; self.delta_poly.coefficients.len()]
        );

        RotationCommitment {
            sender_id: self.my_id,
            commitment: PedersenCommitment::new(&self.delta_poly, &blinding_poly, &g, &h),
        }
    }

    /// Generate delta shares for other participants
    pub fn generate_delta_shares(&self) -> Vec<RotationShare> {
        let mut shares = Vec::new();

        for j in 1..=self.num_participants {
            if j == self.my_id.as_u32() {
                continue;
            }

            let recipient_id = ParticipantId::new(j).unwrap();
            let x = recipient_id.as_scalar();
            let delta = self.delta_poly.evaluate(&x);

            shares.push(RotationShare {
                sender_id: self.my_id,
                recipient_id,
                delta_share: SecretScalar::new(delta),
            });
        }

        shares
    }

    /// Finalize rotation with received shares
    pub fn finalize(
        self,
        received_shares: &[RotationShare],
        commitments: &[RotationCommitment],
    ) -> FrostResult<SecretShare> {
        // Verify we have commitments and shares from all other participants
        if commitments.len() != self.num_participants as usize {
            return Err(FrostError::InsufficientParticipants(
                commitments.len(),
                self.num_participants,
            ));
        }

        if received_shares.len() != (self.num_participants - 1) as usize {
            return Err(FrostError::InsufficientParticipants(
                received_shares.len(),
                self.num_participants - 1,
            ));
        }

        let g = RISTRETTO_BASEPOINT_POINT;
        let h = pedersen_h_generator();

        // Verify each received share
        for share in received_shares {
            let commitment = commitments
                .iter()
                .find(|c| c.sender_id == share.sender_id)
                .ok_or(FrostError::InvalidParticipantIndex(share.sender_id.as_u32()))?;

            // For rotation, blinding is zero
            let zero_blinding = Scalar::ZERO;

            if !commitment.commitment.verify_share(
                self.my_id,
                share.delta_share.as_scalar(),
                &zero_blinding,
                &g,
                &h,
            ) {
                return Err(FrostError::CommitmentVerificationFailed(
                    share.sender_id.as_u32(),
                ));
            }
        }

        // Compute new share: s' = s + Σ δ_i(my_id)
        let mut new_share = *self.current_share.as_scalar();

        // Add my own delta
        new_share += self.delta_poly.evaluate(&self.my_id.as_scalar());

        // Add received deltas
        for share in received_shares {
            new_share += share.delta_share.as_scalar();
        }

        Ok(SecretShare {
            participant_id: self.my_id,
            value: SecretScalar::new(new_share),
            blinding: SecretScalar::new(Scalar::ZERO),
        })
    }
}

/// Commitment to rotation polynomial
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationCommitment {
    /// Sender participant ID
    pub sender_id: ParticipantId,
    /// Commitment to delta polynomial
    pub commitment: PedersenCommitment,
}

/// Delta share for rotation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RotationShare {
    /// Sender participant ID
    pub sender_id: ParticipantId,
    /// Recipient participant ID
    pub recipient_id: ParticipantId,
    /// Delta share δ_i(j)
    pub delta_share: SecretScalar,
}

/// Coordinator for share rotation (for testing)
pub struct RotationCoordinator {
    threshold: u32,
    num_participants: u32,
}

impl RotationCoordinator {
    /// Create new rotation coordinator
    pub fn new(threshold: u32, num_participants: u32) -> FrostResult<Self> {
        if threshold == 0 || threshold > num_participants {
            return Err(FrostError::InvalidThreshold(threshold, num_participants));
        }
        Ok(RotationCoordinator { threshold, num_participants })
    }

    /// Run full rotation protocol
    pub fn run_rotation<R: RngCore + CryptoRng>(
        &self,
        current_shares: &[SecretShare],
        rng: &mut R,
    ) -> FrostResult<Vec<SecretShare>> {
        if current_shares.len() != self.num_participants as usize {
            return Err(FrostError::InsufficientParticipants(
                current_shares.len(),
                self.num_participants,
            ));
        }

        // Create rotation participants
        let mut rotations = Vec::new();
        for share in current_shares {
            rotations.push(ShareRotation::new(
                share.participant_id,
                share,
                self.threshold,
                self.num_participants,
                rng,
            )?);
        }

        // Generate commitments
        let commitments: Vec<_> = rotations
            .iter()
            .map(|r| r.generate_commitments())
            .collect();

        // Generate delta shares
        let all_delta_shares: Vec<Vec<_>> = rotations
            .iter()
            .map(|r| r.generate_delta_shares())
            .collect();

        // Finalize for each participant
        let mut new_shares = Vec::new();
        for (i, rotation) in rotations.into_iter().enumerate() {
            // Collect shares for this participant
            let shares_for_me: Vec<_> = all_delta_shares
                .iter()
                .flat_map(|shares| shares.iter())
                .filter(|s| s.recipient_id == current_shares[i].participant_id)
                .cloned()
                .collect();

            new_shares.push(rotation.finalize(&shares_for_me, &commitments)?);
        }

        Ok(new_shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::DkgCoordinator;
    use crate::signing::{SigningRound1, aggregate_signatures};
    use rand::rngs::OsRng;

    #[test]
    fn test_share_rotation() {
        let mut rng = OsRng;

        // Run DKG
        let dkg_coordinator = DkgCoordinator::new(2, 3).unwrap();
        let dkg_outputs = dkg_coordinator.run_dkg(&mut rng).unwrap();

        let original_pk = dkg_outputs[0].group_public_key.public_key;
        let original_shares: Vec<_> = dkg_outputs
            .iter()
            .map(|o| o.secret_share.clone())
            .collect();

        // Sign a message with original shares
        let message1 = b"Message before rotation";
        let mut round1_states = Vec::new();
        let mut commitments = Vec::new();

        for output in dkg_outputs.iter().take(2) {
            let round1 = SigningRound1::new(
                output.participant_id,
                &output.secret_share,
                &mut rng,
            );
            commitments.push(round1.commitment());
            round1_states.push(round1);
        }

        let mut partial_sigs = Vec::new();
        let mut group_commitment = None;

        for round1 in round1_states.iter().take(2) {
            let round2 = round1.clone().into_round2(message1, &commitments).unwrap();
            if group_commitment.is_none() {
                group_commitment = Some(round2.group_commitment());
            }
            partial_sigs.push(round2.partial_signature());
        }

        let sig1 = aggregate_signatures(message1, &group_commitment.unwrap(), &partial_sigs).unwrap();
        assert!(sig1.verify(message1, &original_pk));

        // Rotate shares
        let rotation_coordinator = RotationCoordinator::new(2, 3).unwrap();
        let new_shares = rotation_coordinator.run_rotation(&original_shares, &mut rng).unwrap();

        // Verify shares are different
        assert_ne!(
            original_shares[0].value.as_scalar(),
            new_shares[0].value.as_scalar()
        );

        // Sign with new shares - should still work with same public key
        let message2 = b"Message after rotation";
        let mut round1_states = Vec::new();
        let mut commitments = Vec::new();

        for i in 0..2 {
            let round1 = SigningRound1::new(
                new_shares[i].participant_id,
                &new_shares[i],
                &mut rng,
            );
            commitments.push(round1.commitment());
            round1_states.push(round1);
        }

        let mut partial_sigs = Vec::new();
        let mut group_commitment = None;

        for round1 in round1_states.iter() {
            let round2 = round1.clone().into_round2(message2, &commitments).unwrap();
            if group_commitment.is_none() {
                group_commitment = Some(round2.group_commitment());
            }
            partial_sigs.push(round2.partial_signature());
        }

        let sig2 = aggregate_signatures(message2, &group_commitment.unwrap(), &partial_sigs).unwrap();

        // Signature should verify with SAME public key
        assert!(sig2.verify(message2, &original_pk));
    }
}
