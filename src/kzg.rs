/// KZG Polynomial Commitment Scheme Implementation
/// 
/// This module implements the Kate-Zaverucha-Goldberg (KZG) polynomial commitment scheme
/// with support for both single-point and multi-point polynomial openings. The implementation
/// is optimized for large-degree polynomials through parallel processing and memory-efficient
/// algorithms.
///
/// Features:
/// - Parallel Common Reference String (CRS) generation
/// - Single and multi-point polynomial evaluations and proofs
/// - Performance monitoring through FFT operation counting
/// - Memory-optimized setup for high-degree polynomials
/// - Bilinear pairing-based verification
///
/// This implementation is designed for use in zero-knowledge proof systems that require
/// efficient polynomial commitments over elliptic curve groups with pairing support.

use std::ops::Mul;
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, Group};
use crate::utils::{div, mul, evaluate, interpolate};
use rayon::prelude::*;
use std::sync::Arc;
use std::time::Instant;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
pub struct KZG<E: Pairing> {
    pub g1: E::G1,
    pub g2: E::G2,
    pub g2_tau: E::G2,
    pub degree: usize,
    pub crs_g1: Vec<E::G1>,
    pub crs_g2: Vec<E::G2>,
    pub fft_counter: Arc<AtomicUsize>,
}

impl<E: Pairing> KZG<E> {
    pub fn new(g1: E::G1, g2: E::G2, degree: usize) -> Self {
        Self {
            g1,
            g2,
            g2_tau: g2.mul(E::ScalarField::ZERO),
            degree,
            crs_g1: vec![],
            crs_g2: vec![],
            fft_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn reset_fft_counter(&self) {
        self.fft_counter.store(0, Ordering::SeqCst);
    }
    
    pub fn get_fft_count(&self) -> usize {
        self.fft_counter.load(Ordering::SeqCst)
    }
    
    pub fn evaluate_poly(&self, poly: &[E::ScalarField], point: E::ScalarField) -> E::ScalarField {
        poly.iter().rev().fold(E::ScalarField::ZERO, |acc, &coeff| acc * point + coeff)
    }

    /// Generates the Common Reference String (CRS) for KZG commitments
    pub fn setup(&mut self, secret: E::ScalarField) {
        let start_time = Instant::now();
        
        // Initialize vectors with proper capacity
        self.crs_g1 = Vec::with_capacity(self.degree + 1);
        self.crs_g2 = Vec::with_capacity(self.degree + 1);
        
        // Parallel processing configuration
        let chunk_size = 10000;
        let num_chunks = (self.degree + chunk_size) / chunk_size;
        
        let g1 = Arc::new(self.g1);
        let g2 = Arc::new(self.g2);
        
        // Pre-compute powers of secret
        let mut powers: Vec<E::ScalarField> = Vec::with_capacity(self.degree + 1);
        let mut current_power = E::ScalarField::ONE;
        powers.push(current_power);
        
        for _ in 1..=self.degree {
            current_power *= secret;
            powers.push(current_power);
        }
        
        // Generate G1 elements in parallel
        let crs_g1_chunks: Vec<Vec<E::G1>> = (0..num_chunks)
            .into_par_iter()
            .map(|chunk_idx| {
                let start_idx = chunk_idx * chunk_size;
                let end_idx = std::cmp::min(start_idx + chunk_size, self.degree + 1);
                
                let g1_ref = Arc::clone(&g1);
                let powers_slice = &powers[start_idx..end_idx];
                
                powers_slice.iter()
                    .map(|power| g1_ref.mul(*power))
                    .collect()
            })
            .collect();
        
        // Combine G1 chunks
        let mut all_crs_g1 = Vec::new();
        for chunk in crs_g1_chunks {
            all_crs_g1.extend(chunk);
        }
        
        // Generate G2 elements in parallel
        let crs_g2_chunks: Vec<Vec<E::G2>> = (0..num_chunks)
            .into_par_iter()
            .map(|chunk_idx| {
                let start_idx = chunk_idx * chunk_size;
                let end_idx = std::cmp::min(start_idx + chunk_size, self.degree + 1);
                
                let g2_ref = Arc::clone(&g2);
                let powers_slice = &powers[start_idx..end_idx];
                
                powers_slice.iter()
                    .map(|power| g2_ref.mul(*power))
                    .collect()
            })
            .collect();
        
        // Combine G2 chunks
        let mut all_crs_g2 = Vec::new();
        for chunk in crs_g2_chunks {
            all_crs_g2.extend(chunk);
        }
        
        self.crs_g1 = all_crs_g1;
        self.crs_g2 = all_crs_g2;
        self.g2_tau = self.g2.mul(secret);
    }

    /// Commits to a polynomial using the KZG scheme
    pub fn commit(&self, poly: &[E::ScalarField]) -> E::G1 {
        if poly.len() > 64 {
            self.fft_counter.fetch_add(1, Ordering::SeqCst);
        }
        
        let mut commitment = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..std::cmp::min(poly.len(), self.crs_g1.len()) {
            commitment += self.crs_g1[i] * poly[i];
        }
        commitment
    }

    /// Generates an opening proof for a polynomial at a specific point
    pub fn open(&self, poly: &[E::ScalarField], point: E::ScalarField) -> E::G1 {
        let value = evaluate(poly, point);
        let denominator = [-point, E::ScalarField::ONE];
        
        let first = poly[0] - value;
        let rest = &poly[1..];
        let temp: Vec<E::ScalarField> = std::iter::once(first)
            .chain(rest.iter().cloned())
            .collect();
        let numerator: &[E::ScalarField] = &temp;
        
        let quotient = div(numerator, &denominator).unwrap();
        
        let mut pi = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..quotient.len() {
            pi += self.crs_g1[i] * quotient[i];
        }
        
        pi
    }

    /// Generates a multi-point opening proof for a polynomial
    pub fn multi_open(&self, poly: &[E::ScalarField], points: &[E::ScalarField]) -> E::G1 {
        // Construct zero polynomial with given points as roots
        let mut zero_poly = vec![-points[0], E::ScalarField::ONE];
        for i in 1..points.len() {
            zero_poly = mul(&zero_poly, &[-points[i], E::ScalarField::ONE]);
        }

        // Compute values at all points
        let mut values = vec![];
        for i in 0..points.len() {
            values.push(evaluate(poly, points[i]));
        }
        
        // Lagrange interpolation
        let mut lagrange_poly = interpolate(points, &values).unwrap();
        lagrange_poly.resize(poly.len(), E::ScalarField::ZERO);

        // Compute numerator polynomial
        let mut numerator = Vec::with_capacity(poly.len());
        for (coeff1, coeff2) in poly.iter().zip(lagrange_poly.as_slice()) {
            numerator.push(*coeff1 - coeff2);
        }

        let quotient = div(&numerator, &zero_poly).unwrap();

        let mut pi = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..quotient.len() {
            pi += self.crs_g1[i] * quotient[i];
        }
        
        pi
    }

    /// Verifies a single-point opening proof
    pub fn verify(
        &self,
        point: E::ScalarField,
        value: E::ScalarField,
        commitment: E::G1,
        pi: E::G1
    ) -> bool {
        let g2_point = self.g2.mul(point);
        let g1_value = self.g1.mul(value);
        let lhs_g2 = self.g2_tau - g2_point;
        let rhs_g1 = commitment - g1_value;
        
        let lhs = E::pairing(pi, lhs_g2);
        let rhs = E::pairing(rhs_g1, self.g2);
        
        lhs == rhs
    }

    /// Verifies a multi-point opening proof
    pub fn verify_multi(
        &self,
        points: &[E::ScalarField],
        values: &[E::ScalarField],
        commitment: E::G1,
        pi: E::G1
    ) -> bool {
        // Compute zero polynomial
        let mut zero_poly = vec![-points[0], E::ScalarField::ONE];
        for i in 1..points.len() {
            zero_poly = mul(&zero_poly, &[-points[i], E::ScalarField::ONE]);
        }

        // Commit to zero polynomial in G2
        let mut zero_commitment = self.g2.mul(E::ScalarField::ZERO);
        for i in 0..zero_poly.len() {
            zero_commitment += self.crs_g2[i] * zero_poly[i];
        }

        // Compute Lagrange polynomial
        let lagrange_poly = interpolate(points, &values).unwrap();

        // Commit to Lagrange polynomial in G1
        let mut lagrange_commitment = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..lagrange_poly.len() {
            lagrange_commitment += self.crs_g1[i] * lagrange_poly[i];
        }

        let lhs = E::pairing(pi, zero_commitment);
        let rhs = E::pairing(commitment - lagrange_commitment, self.g2);
        lhs == rhs
    }
}
