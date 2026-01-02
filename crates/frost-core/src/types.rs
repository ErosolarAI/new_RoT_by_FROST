//! Core types for FROST protocol

use curve25519_dalek::{
    ristretto::{RistrettoPoint, CompressedRistretto},
    scalar::Scalar,
    traits::Identity,
};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Participant identifier (1-indexed)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub u32);

impl ParticipantId {
    /// Create a new participant ID
    pub fn new(id: u32) -> Option<Self> {
        if id > 0 {
            Some(ParticipantId(id))
        } else {
            None
        }
    }

    /// Get the underlying u32 value
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Convert to Scalar for polynomial evaluation
    pub fn as_scalar(&self) -> Scalar {
        Scalar::from(self.0)
    }
}

/// Secret scalar value (auto-zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretScalar(pub(crate) Scalar);

impl SecretScalar {
    /// Create from a Scalar
    pub fn new(scalar: Scalar) -> Self {
        SecretScalar(scalar)
    }

    /// Get reference to inner scalar (use carefully)
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }
}

/// Polynomial of degree t-1 for secret sharing
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Polynomial {
    /// Coefficients [a0, a1, ..., a_{t-1}]
    pub(crate) coefficients: Vec<SecretScalar>,
}

impl Polynomial {
    /// Create a new polynomial with given coefficients
    pub fn new(coefficients: Vec<Scalar>) -> Self {
        Polynomial {
            coefficients: coefficients.into_iter().map(SecretScalar::new).collect(),
        }
    }

    /// Generate random polynomial of degree t-1 with given constant term
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(
        degree: u32,
        constant_term: Scalar,
        rng: &mut R,
    ) -> Self {
        let mut coefficients = vec![SecretScalar::new(constant_term)];
        for _ in 0..degree {
            coefficients.push(SecretScalar::new(Scalar::random(rng)));
        }
        Polynomial { coefficients }
    }

    /// Evaluate polynomial at given x using Horner's method
    pub fn evaluate(&self, x: &Scalar) -> Scalar {
        if self.coefficients.is_empty() {
            return Scalar::ZERO;
        }

        let mut result = *self.coefficients.last().unwrap().as_scalar();
        for coeff in self.coefficients.iter().rev().skip(1) {
            result = result * x + coeff.as_scalar();
        }
        result
    }

    /// Get degree of polynomial
    pub fn degree(&self) -> usize {
        self.coefficients.len().saturating_sub(1)
    }
}

/// Pedersen commitment to polynomial coefficients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenCommitment {
    /// Commitments C_i = a_i * G + b_i * H for each coefficient
    pub commitments: Vec<CompressedRistretto>,
}

impl PedersenCommitment {
    /// Create commitment from two polynomials
    pub fn new(
        f: &Polynomial,
        g: &Polynomial,
        generator_g: &RistrettoPoint,
        generator_h: &RistrettoPoint,
    ) -> Self {
        assert_eq!(f.coefficients.len(), g.coefficients.len());

        let commitments = f.coefficients.iter()
            .zip(g.coefficients.iter())
            .map(|(a, b)| {
                (a.as_scalar() * generator_g + b.as_scalar() * generator_h).compress()
            })
            .collect();

        PedersenCommitment { commitments }
    }

    /// Verify that a share lies on the committed polynomial
    pub fn verify_share(
        &self,
        participant_id: ParticipantId,
        share: &Scalar,
        blinding: &Scalar,
        generator_g: &RistrettoPoint,
        generator_h: &RistrettoPoint,
    ) -> bool {
        // Compute share * G + blinding * H
        let lhs = share * generator_g + blinding * generator_h;

        // Compute Σ C_k * x^k where x is participant ID
        let x = participant_id.as_scalar();
        let mut x_power = Scalar::ONE;
        let mut rhs = RistrettoPoint::identity();

        for commitment in &self.commitments {
            if let Some(point) = commitment.decompress() {
                rhs += x_power * point;
                x_power *= x;
            } else {
                return false;
            }
        }

        lhs == rhs
    }
}

/// Secret share for a participant
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretShare {
    /// Participant ID
    pub participant_id: ParticipantId,
    /// Secret share value
    pub value: SecretScalar,
    /// Blinding factor for Pedersen commitment
    pub blinding: SecretScalar,
}

/// Public key share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyShare {
    /// Participant ID
    pub participant_id: ParticipantId,
    /// Public key point Y_i = s_i * G
    pub public_key: CompressedRistretto,
}

/// Group public key and verification shares
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPublicKey {
    /// The group's public key PK = s * G
    pub public_key: CompressedRistretto,
    /// Public key shares for each participant
    pub participant_shares: Vec<PublicKeyShare>,
    /// Threshold value
    pub threshold: u32,
    /// Total number of participants
    pub num_participants: u32,
}

impl GroupPublicKey {
    /// Verify a Schnorr signature
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &SchnorrSignature,
    ) -> bool {
        signature.verify(message, &self.public_key)
    }
}

/// Schnorr signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrSignature {
    /// Challenge response z
    pub z: [u8; 32],
    /// Commitment R
    pub commitment: CompressedRistretto,
}

impl SchnorrSignature {
    /// Verify signature against public key
    pub fn verify(&self, message: &[u8], public_key: &CompressedRistretto) -> bool {
        use sha2::{Sha512, Digest};

        let pk = match public_key.decompress() {
            Some(pk) => pk,
            None => return false,
        };

        let r = match self.commitment.decompress() {
            Some(r) => r,
            None => return false,
        };

        let z = match Scalar::from_canonical_bytes(self.z) {
            Some(z) => z,
            None => return false,
        };

        // Compute challenge c = H(R || PK || m)
        let mut hasher = Sha512::new();
        hasher.update(r.compress().as_bytes());
        hasher.update(public_key.as_bytes());
        hasher.update(message);
        let challenge = Scalar::from_hash(hasher);

        // Verify: z * G == R + c * PK
        let lhs = z * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let rhs = r + challenge * pk;

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_participant_id() {
        assert!(ParticipantId::new(0).is_none());
        assert!(ParticipantId::new(1).is_some());
        assert_eq!(ParticipantId::new(5).unwrap().as_u32(), 5);
    }

    #[test]
    fn test_polynomial_evaluation() {
        // f(x) = 3 + 2x + x^2
        let poly = Polynomial::new(vec![
            Scalar::from(3u64),
            Scalar::from(2u64),
            Scalar::from(1u64),
        ]);

        // f(0) = 3
        assert_eq!(poly.evaluate(&Scalar::ZERO), Scalar::from(3u64));

        // f(1) = 3 + 2 + 1 = 6
        assert_eq!(poly.evaluate(&Scalar::ONE), Scalar::from(6u64));

        // f(2) = 3 + 4 + 4 = 11
        assert_eq!(poly.evaluate(&Scalar::from(2u64)), Scalar::from(11u64));
    }

    #[test]
    fn test_polynomial_random() {
        let mut rng = OsRng;
        let constant = Scalar::from(42u64);
        let poly = Polynomial::random(2, constant, &mut rng);

        assert_eq!(poly.degree(), 2);
        assert_eq!(poly.evaluate(&Scalar::ZERO), constant);
    }

    #[test]
    fn test_pedersen_commitment() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

        let mut rng = OsRng;
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = RistrettoPoint::random(&mut rng);

        let f = Polynomial::random(1, Scalar::from(42u64), &mut rng);
        let g_poly = Polynomial::random(1, Scalar::random(&mut rng), &mut rng);

        let commitment = PedersenCommitment::new(&f, &g_poly, &g, &h);

        // Verify share for participant 1
        let id = ParticipantId::new(1).unwrap();
        let share = f.evaluate(&id.as_scalar());
        let blinding = g_poly.evaluate(&id.as_scalar());

        assert!(commitment.verify_share(id, &share, &blinding, &g, &h));
    }
}
