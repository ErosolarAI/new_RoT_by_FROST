//! Distributed Key Generation (DKG) Protocol
//!
//! Implements Pedersen DKG for FROST threshold signatures.
//! Protocol flow:
//! 1. Each participant generates secret polynomial and commitments
//! 2. Participants exchange shares
//! 3. Participants verify received shares against commitments
//! 4. Participants aggregate shares to get final secret share

use crate::types::*;
use crate::{FrostError, FrostResult};
use curve25519_dalek::{
    ristretto::{RistrettoPoint, CompressedRistretto},
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
    traits::Identity,
};
use rand_core::{RngCore, CryptoRng};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Alternative basepoint for Pedersen commitments (nothing-up-my-sleeve)
/// H = hash_to_point("FROST-RISTRETTO255-SHA512-v1-PEDERSEN-H")
pub fn pedersen_h_generator() -> RistrettoPoint {
    use sha2::{Sha512, Digest};
    let mut hasher = Sha512::new();
    hasher.update(b"FROST-RISTRETTO255-SHA512-v1-PEDERSEN-H");
    RistrettoPoint::from_hash(hasher)
}

/// DKG participant state machine
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DkgParticipant {
    /// My participant ID
    my_id: ParticipantId,
    /// Threshold value (t)
    threshold: u32,
    /// Total number of participants (n)
    num_participants: u32,
    /// My secret polynomial f(x)
    secret_poly: Polynomial,
    /// My blinding polynomial g(x)
    blinding_poly: Polynomial,
    /// Generator G
    #[zeroize(skip)]
    generator_g: RistrettoPoint,
    /// Generator H for Pedersen commitments
    #[zeroize(skip)]
    generator_h: RistrettoPoint,
}

impl DkgParticipant {
    /// Create new DKG participant
    pub fn new<R: RngCore + CryptoRng>(
        my_id: ParticipantId,
        threshold: u32,
        num_participants: u32,
        rng: &mut R,
    ) -> FrostResult<Self> {
        if threshold == 0 || threshold > num_participants {
            return Err(FrostError::InvalidThreshold(threshold, num_participants));
        }

        if my_id.as_u32() == 0 || my_id.as_u32() > num_participants {
            return Err(FrostError::InvalidParticipantIndex(my_id.as_u32()));
        }

        // Generate random polynomials of degree t-1
        let secret_poly = Polynomial::random(
            threshold - 1,
            Scalar::random(rng),
            rng,
        );

        let blinding_poly = Polynomial::random(
            threshold - 1,
            Scalar::random(rng),
            rng,
        );

        Ok(DkgParticipant {
            my_id,
            threshold,
            num_participants,
            secret_poly,
            blinding_poly,
            generator_g: RISTRETTO_BASEPOINT_POINT,
            generator_h: pedersen_h_generator(),
        })
    }

    /// Round 1: Generate and broadcast commitments
    pub fn round1_broadcast(&self) -> DkgRound1Broadcast {
        DkgRound1Broadcast {
            sender_id: self.my_id,
            commitment: PedersenCommitment::new(
                &self.secret_poly,
                &self.blinding_poly,
                &self.generator_g,
                &self.generator_h,
            ),
        }
    }

    /// Round 2: Generate shares for each other participant
    pub fn round2_secret_shares(&self) -> Vec<DkgRound2P2PMessage> {
        let mut messages = Vec::new();

        for j in 1..=self.num_participants {
            if j == self.my_id.as_u32() {
                continue; // Don't send to self
            }

            let recipient_id = ParticipantId::new(j).unwrap();
            let x = recipient_id.as_scalar();

            let secret_share = self.secret_poly.evaluate(&x);
            let blinding_share = self.blinding_poly.evaluate(&x);

            messages.push(DkgRound2P2PMessage {
                sender_id: self.my_id,
                recipient_id,
                secret_share: SecretScalar::new(secret_share),
                blinding_share: SecretScalar::new(blinding_share),
            });
        }

        messages
    }

    /// Verify and finalize DKG
    pub fn finalize(
        &self,
        round1_broadcasts: &[DkgRound1Broadcast],
        round2_shares: &[DkgRound2P2PMessage],
    ) -> FrostResult<DkgOutput> {
        // Verify we have commitments from all participants
        if round1_broadcasts.len() != self.num_participants as usize {
            return Err(FrostError::InsufficientParticipants(
                round1_broadcasts.len(),
                self.num_participants,
            ));
        }

        // Verify we have shares from all other participants
        if round2_shares.len() != (self.num_participants - 1) as usize {
            return Err(FrostError::InsufficientParticipants(
                round2_shares.len(),
                self.num_participants - 1,
            ));
        }

        // Verify each received share against the sender's commitment
        for share_msg in round2_shares {
            // Find commitment from this sender
            let commitment = round1_broadcasts
                .iter()
                .find(|b| b.sender_id == share_msg.sender_id)
                .ok_or(FrostError::InvalidParticipantIndex(share_msg.sender_id.as_u32()))?
                .commitment
                .clone();

            // Verify share
            if !commitment.verify_share(
                self.my_id,
                share_msg.secret_share.as_scalar(),
                share_msg.blinding_share.as_scalar(),
                &self.generator_g,
                &self.generator_h,
            ) {
                return Err(FrostError::CommitmentVerificationFailed(
                    share_msg.sender_id.as_u32(),
                ));
            }
        }

        // Aggregate shares (including our own)
        let mut aggregated_secret = self.secret_poly.evaluate(&self.my_id.as_scalar());

        for share_msg in round2_shares {
            aggregated_secret += share_msg.secret_share.as_scalar();
        }

        // Compute group public key from commitments
        let mut group_public_key = RistrettoPoint::identity();
        for broadcast in round1_broadcasts {
            if let Some(commitment) = broadcast.commitment.commitments.first() {
                if let Some(point) = commitment.decompress() {
                    group_public_key += point;
                }
            }
        }

        // Compute verification shares for each participant
        let mut verification_shares = Vec::new();
        for i in 1..=self.num_participants {
            let participant_id = ParticipantId::new(i).unwrap();
            let x = participant_id.as_scalar();
            let mut x_power = Scalar::ONE;
            let mut vss_point = RistrettoPoint::identity();

            for broadcast in round1_broadcasts {
                for commitment in &broadcast.commitment.commitments {
                    if let Some(point) = commitment.decompress() {
                        vss_point += x_power * point;
                        x_power *= x;
                    }
                }
            }

            verification_shares.push(PublicKeyShare {
                participant_id,
                public_key: vss_point.compress(),
            });
        }

        Ok(DkgOutput {
            participant_id: self.my_id,
            secret_share: SecretShare {
                participant_id: self.my_id,
                value: SecretScalar::new(aggregated_secret),
                blinding: SecretScalar::new(Scalar::ZERO), // Not needed post-DKG
            },
            group_public_key: GroupPublicKey {
                public_key: group_public_key.compress(),
                participant_shares: verification_shares,
                threshold: self.threshold,
                num_participants: self.num_participants,
            },
        })
    }
}

/// Round 1 broadcast message (commitments)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound1Broadcast {
    /// Sender participant ID
    pub sender_id: ParticipantId,
    /// Pedersen commitment to polynomial
    pub commitment: PedersenCommitment,
}

/// Round 2 point-to-point message (secret shares)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DkgRound2P2PMessage {
    /// Sender participant ID
    pub sender_id: ParticipantId,
    /// Recipient participant ID
    pub recipient_id: ParticipantId,
    /// Secret share s_{i,j} = f_i(j)
    pub secret_share: SecretScalar,
    /// Blinding share t_{i,j} = g_i(j)
    pub blinding_share: SecretScalar,
}

/// Output of successful DKG
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DkgOutput {
    /// Participant ID
    #[zeroize(skip)]
    pub participant_id: ParticipantId,
    /// This participant's secret share
    pub secret_share: SecretShare,
    /// Group public key and verification data
    #[zeroize(skip)]
    pub group_public_key: GroupPublicKey,
}

/// Simplified DKG coordinator (for testing/simulation)
pub struct DkgCoordinator {
    threshold: u32,
    num_participants: u32,
}

impl DkgCoordinator {
    /// Create new DKG coordinator
    pub fn new(threshold: u32, num_participants: u32) -> FrostResult<Self> {
        if threshold == 0 || threshold > num_participants {
            return Err(FrostError::InvalidThreshold(threshold, num_participants));
        }
        Ok(DkgCoordinator { threshold, num_participants })
    }

    /// Run full DKG protocol (for testing - in production this is distributed)
    pub fn run_dkg<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> FrostResult<Vec<DkgOutput>> {
        // Create participants
        let mut participants = Vec::new();
        for i in 1..=self.num_participants {
            let id = ParticipantId::new(i).unwrap();
            participants.push(DkgParticipant::new(id, self.threshold, self.num_participants, rng)?);
        }

        // Round 1: Collect commitments
        let round1_broadcasts: Vec<_> = participants
            .iter()
            .map(|p| p.round1_broadcast())
            .collect();

        // Round 2: Collect secret shares
        let round2_messages: Vec<Vec<_>> = participants
            .iter()
            .map(|p| p.round2_secret_shares())
            .collect();

        // Finalize for each participant
        let mut outputs = Vec::new();
        for (i, participant) in participants.iter().enumerate() {
            // Collect shares destined for this participant
            let shares_for_me: Vec<_> = round2_messages
                .iter()
                .flat_map(|msgs| msgs.iter())
                .filter(|msg| msg.recipient_id == participant.my_id)
                .cloned()
                .collect();

            outputs.push(participant.finalize(&round1_broadcasts, &shares_for_me)?);
        }

        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_dkg_simple() {
        let mut rng = OsRng;
        let coordinator = DkgCoordinator::new(2, 3).unwrap();
        let outputs = coordinator.run_dkg(&mut rng).unwrap();

        assert_eq!(outputs.len(), 3);

        // All participants should have the same group public key
        let pk = &outputs[0].group_public_key.public_key;
        assert!(outputs.iter().all(|o| &o.group_public_key.public_key == pk));

        // All should have correct threshold
        assert!(outputs.iter().all(|o| o.group_public_key.threshold == 2));
    }

    #[test]
    fn test_dkg_invalid_threshold() {
        assert!(DkgCoordinator::new(0, 3).is_err());
        assert!(DkgCoordinator::new(4, 3).is_err());
    }
}
