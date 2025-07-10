/// Aggregated Subvector Commitment (ASVC) Implementation
///
/// This module implements aggregated subvector commitments based on polynomial
/// commitment schemes over bilinear groups. The construction enables efficient
/// commitment to vectors with selective opening and aggregation capabilities.
///
/// Core functionality includes:
/// - Vector commitment with position-wise opening
/// - Subvector proof generation and verification
/// - Proof aggregation for multiple positions
/// - Lagrange interpolation-based construction

use std::ops::{Mul, Div};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use crate::utils::{get_omega, mul, div, scalar_mul, interpolate, evaluate};

/// Common Reference String for bilinear group operations
#[derive(Clone)]
pub struct CRS<E: Pairing> {
    pub g1: Vec<E::G1>,
    pub g2: Vec<E::G2>
}

/// Update key for commitment updates (currently not implemented)
#[derive(Clone)]
pub struct UpdateKey<E: Pairing> {
    pub ai_commitment: Vec<E::G1>,
    pub ui_commitment: Vec<E::G1>
}

/// Proving key containing CRS and Lagrange basis commitments
pub struct ProvingKey<E: Pairing> {
    pub crs: CRS<E>,
    pub update_key: UpdateKey<E>,
    pub li_commitment: Vec<E::G1>
}

/// Verification key for proof verification
pub struct VerificationKey<E: Pairing> {
    pub crs: CRS<E>,
    pub a_commitment: E::G1
}

/// Main ASVC structure with keys and parameters
pub struct ASVC<E: Pairing> {
    pub degree: usize,
    pub update_key: UpdateKey<E>,
    pub proving_key: ProvingKey<E>,
    pub verification_key: VerificationKey<E>
}

impl<E: Pairing> ASVC<E> {
    /// Generate keys for ASVC scheme
    /// 
    /// Creates the necessary cryptographic keys including the common reference string,
    /// Lagrange basis commitments, and update keys for the given degree and secret.
    pub fn key_gen(g1: E::G1, g2: E::G2, degree: usize, secret: E::ScalarField) -> Self {
        // Generate common reference string
        let mut crs_g1: Vec<E::G1> = Vec::new();
        let mut crs_g2: Vec<E::G2> = Vec::new();
        for i in 0..=degree {
            crs_g1.push(g1.mul(secret.pow(&[i as u64])));
            crs_g2.push(g2.mul(secret.pow(&[i as u64])));
        }

        // Compute a_commitment as [τ^n - 1]₁
        let a_commitment: E::G1 = crs_g1[degree] - crs_g1[0];

        // Initialize commitment vectors
        let mut ai_commitment = vec![g1; degree];
        let mut li_commitment = vec![g1; degree];
        let mut ui_commitment = vec![g1; degree];

        // Compute vanishing polynomial: X^n - 1
        let mut vanishing_poly = vec![E::ScalarField::ZERO; degree + 1];
        vanishing_poly[0] = -E::ScalarField::ONE;
        vanishing_poly[degree] = E::ScalarField::ONE;
        
        let omega = get_omega(&vec![E::ScalarField::ZERO; degree]);
        
        for i in 0..degree {
            // Compute denominator polynomial: X - ω^i
            let denominator = vec![-omega.pow([i as u64]), E::ScalarField::ONE];
            
            // Compute aᵢ(X) = (X^n - 1) / (X - ω^i)
            let ai_polynomial = div(&vanishing_poly, &denominator)
                .expect("Division should succeed for vanishing polynomial");

            // Compute Lagrange basis: Lᵢ(X) = aᵢ(X) / (n * ω^i)
            let denominator_eval = E::ScalarField::from(degree as u32) * omega.pow([i as u64]);
            let li_polynomial = scalar_mul(&ai_polynomial, denominator_eval.inverse().unwrap());

            // Compute uᵢ(X) = (Lᵢ(X) - 1) / (X - ω^i)
            let mut ui_numerator = li_polynomial.clone();
            ui_numerator[0] -= E::ScalarField::ONE;
            let ui_polynomial = div(&ui_numerator, &denominator)
                .expect("Division should succeed for Lagrange polynomial");

            // Commit polynomials to group elements
            ai_commitment[i] = commit_polynomial(&crs_g1, &ai_polynomial);
            li_commitment[i] = commit_polynomial(&crs_g1, &li_polynomial);
            ui_commitment[i] = commit_polynomial(&crs_g1, &ui_polynomial);
        }

        let update_key = UpdateKey {
            ai_commitment,
            ui_commitment
        };
        
        let crs = CRS {
            g1: crs_g1,
            g2: crs_g2
        };

        Self {
            degree,
            update_key: update_key.clone(),
            proving_key: ProvingKey {
                crs: crs.clone(),
                update_key: update_key.clone(),
                li_commitment
            },
            verification_key: VerificationKey {
                crs: crs.clone(),
                a_commitment
            }
        }
    }

    /// Commit to a vector using Lagrange interpolation
    /// 
    /// Creates a commitment to the input vector by computing the inner product
    /// with the precomputed Lagrange basis commitments.
    pub fn vector_commit(&self, vector: &[E::ScalarField]) -> E::G1 {
        if vector.len() != self.proving_key.li_commitment.len() {
            panic!("Vector length {} does not match commitment length {}", 
                   vector.len(), self.proving_key.li_commitment.len());
        }

        let mut commitment = self.proving_key.crs.g1[0].mul(E::ScalarField::ZERO);
        for i in 0..vector.len() {
            commitment += self.proving_key.li_commitment[i] * vector[i];
        }
        commitment
    }

    /// Generate proof for specific positions in the vector
    /// 
    /// Creates a proof that the committed vector has specific values at the
    /// given indices using polynomial division and commitment.
    pub fn prove_position(&self, indices: &[usize], vector: &[E::ScalarField]) -> Result<E::G1, String> {
        if indices.is_empty() {
            return Err("Cannot prove empty index set".to_string());
        }

        // Interpolate vector as polynomial
        let points: Vec<E::ScalarField> = (0..vector.len())
            .map(|i| E::ScalarField::from(i as u32))
            .collect();
        let numerator = interpolate(&points, vector)
            .map_err(|e| format!("Interpolation failed: {}", e))?;

        // Compute denominator as product of (X - ω^i) for i in indices
        let omega = get_omega(&vec![E::ScalarField::ZERO; vector.len()]);
        let mut denominator = vec![-omega.pow([indices[0] as u64]), E::ScalarField::ONE];
        
        for &i in &indices[1..] {
            let factor = vec![-omega.pow([i as u64]), E::ScalarField::ONE];
            denominator = mul(&denominator, &factor);
        }

        // Compute quotient polynomial
        let quotient = div(&numerator, &denominator)
            .map_err(|e| format!("Polynomial division failed: {}", e))?;
        
        // Commit quotient to get proof
        Ok(commit_polynomial(&self.proving_key.crs.g1, &quotient))
    }

    /// Verify subvector commitment proof
    /// 
    /// Verifies that the given proof correctly opens the commitment to the
    /// specified subvector at the given indices.
    pub fn verify_position(
        &self,
        commitment: E::G1,
        indices: &[usize],
        subvector: &[E::ScalarField],
        pi: E::G1
    ) -> bool {
        if indices.len() != subvector.len() {
            return false;
        }

        if indices.is_empty() {
            return true;
        }

        // Compute denominator polynomial
        let omega = get_omega(&vec![E::ScalarField::ZERO; self.degree]);
        let mut denominator = vec![-omega.pow([indices[0] as u64]), E::ScalarField::ONE];
        
        for &i in &indices[1..] {
            let factor = vec![-omega.pow([i as u64]), E::ScalarField::ONE];
            denominator = mul(&denominator, &factor);
        }

        // Commit denominator in G2
        let denominator_commitment = commit_polynomial(&self.verification_key.crs.g2, &denominator);

        // Interpolate subvector at indices
        let indices_field: Vec<E::ScalarField> = indices.iter()
            .map(|&i| E::ScalarField::from(i as u32))
            .collect();
        
        let remainder = match interpolate(&indices_field, subvector) {
            Ok(poly) => poly,
            Err(_) => return false,
        };

        // Commit remainder in G1
        let remainder_commitment = commit_polynomial(&self.verification_key.crs.g1, &remainder);

        // Verify pairing equation: e(π, [denominator]₂) = e(C - [remainder]₁, [1]₂)
        let lhs = E::pairing(pi, denominator_commitment);
        let rhs = E::pairing(commitment - remainder_commitment, self.verification_key.crs.g2[0]);
        lhs == rhs
    }

    /// Aggregate multiple proofs into a single proof
    /// 
    /// Combines proofs for different positions into a single aggregated proof
    /// using the derivative of the vanishing polynomial.
    pub fn aggregate_proofs(&self, indices: &[usize], proofs: Vec<E::G1>) -> Result<E::G1, String> {
        if indices.len() != proofs.len() {
            return Err("Number of indices must match number of proofs".to_string());
        }

        if indices.is_empty() {
            return Err("Cannot aggregate empty proof set".to_string());
        }

        // Compute vanishing polynomial A(X) = ∏(X - ω^i)
        let omega = get_omega(&vec![E::ScalarField::ZERO; self.degree]);
        let mut vanishing_poly = vec![-omega.pow([indices[0] as u64]), E::ScalarField::ONE];
        
        for &i in &indices[1..] {
            let factor = vec![-omega.pow([i as u64]), E::ScalarField::ONE];
            vanishing_poly = mul(&vanishing_poly, &factor);
        }

        // Compute derivative A'(X)
        let mut derivative = vec![E::ScalarField::ZERO; vanishing_poly.len().saturating_sub(1)];
        for i in 1..vanishing_poly.len() {
            derivative[i - 1] = vanishing_poly[i] * E::ScalarField::from(i as u32);
        }

        // Aggregate proofs: ∑ πᵢ * A'(ωⁱ)
        let mut aggregated_proof = self.proving_key.crs.g1[0].mul(E::ScalarField::ZERO);
        for (k, &i) in indices.iter().enumerate() {
            let eval_point = omega.pow([i as u64]);
            let weight = evaluate(&derivative, eval_point);
            aggregated_proof += proofs[k].mul(weight);
        }

        Ok(aggregated_proof)
    }
}

/// Helper function to commit a polynomial to a group element
fn commit_polynomial<G, F>(crs: &[G], polynomial: &[F]) -> G 
where
    G: Mul<F, Output = G> + std::ops::Add<Output = G> + Copy,
    F: Field,
{
    let mut commitment = crs[0].mul(F::ZERO);
    for (i, &coeff) in polynomial.iter().enumerate() {
        if i < crs.len() {
            commitment = commitment + crs[i].mul(coeff);
        }
    }
    commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
    use ark_ff::{UniformRand, One};
    use ark_std::test_rng;

    type TestField = Fr;
    type TestG1 = G1Projective;
    type TestG2 = G2Projective;

    #[test]
    fn test_vector_commit_and_prove() {
        let rng = &mut test_rng();
        let degree = 8;
        let secret = TestField::rand(rng);
        let g1 = TestG1::rand(rng);
        let g2 = TestG2::rand(rng);

        let asvc = ASVC::<Bls12_381>::key_gen(g1, g2, degree, secret);

        // Create test vector
        let vector: Vec<TestField> = (0..degree)
            .map(|i| TestField::from((i + 1) as u64))
            .collect();

        // Commit to vector
        let commitment = asvc.vector_commit(&vector);

        // Test single position proof
        let indices = vec![2];
        let subvector = vec![vector[2]];
        
        let proof = asvc.prove_position(&indices, &vector).unwrap();
        let verified = asvc.verify_position(commitment, &indices, &subvector, proof);
        
        assert!(verified, "Single position proof should verify");
    }

    #[test]
    fn test_multiple_position_proof() {
        let rng = &mut test_rng();
        let degree = 8;
        let secret = TestField::rand(rng);
        let g1 = TestG1::rand(rng);
        let g2 = TestG2::rand(rng);

        let asvc = ASVC::<Bls12_381>::key_gen(g1, g2, degree, secret);

        // Create test vector
        let vector: Vec<TestField> = (0..degree)
            .map(|i| TestField::from((i * 2 + 1) as u64))
            .collect();

        // Commit to vector
        let commitment = asvc.vector_commit(&vector);

        // Test multiple position proof
        let indices = vec![1, 3, 5];
        let subvector = vec![vector[1], vector[3], vector[5]];
        
        let proof = asvc.prove_position(&indices, &vector).unwrap();
        let verified = asvc.verify_position(commitment, &indices, &subvector, proof);
        
        assert!(verified, "Multiple position proof should verify");
    }

    #[test]
    fn test_invalid_proof() {
        let rng = &mut test_rng();
        let degree = 8;
        let secret = TestField::rand(rng);
        let g1 = TestG1::rand(rng);
        let g2 = TestG2::rand(rng);

        let asvc = ASVC::<Bls12_381>::key_gen(g1, g2, degree, secret);

        // Create test vector
        let vector: Vec<TestField> = (0..degree)
            .map(|i| TestField::from((i + 1) as u64))
            .collect();

        // Commit to vector
        let commitment = asvc.vector_commit(&vector);

        // Create proof for correct values
        let indices = vec![2];
        let correct_subvector = vec![vector[2]];
        let proof = asvc.prove_position(&indices, &vector).unwrap();

        // Try to verify with incorrect values
        let incorrect_subvector = vec![TestField::from(999u64)];
        let verified = asvc.verify_position(commitment, &indices, &incorrect_subvector, proof);
        
        assert!(!verified, "Proof with incorrect values should not verify");
    }
}
