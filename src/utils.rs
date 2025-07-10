/// Polynomial Arithmetic Utilities
/// 
/// This module provides essential polynomial operations for cryptographic applications,
/// including arithmetic operations, evaluation, interpolation, and roots of unity
/// computation. All operations are generic over finite fields supporting the
/// arkworks ecosystem.
///
/// Functions include:
/// - Basic arithmetic: addition, multiplication, division, scalar multiplication
/// - Polynomial evaluation using Horner's method optimization
/// - Lagrange interpolation for polynomial reconstruction
/// - Roots of unity computation for FFT operations

use ark_ff::{Field, PrimeField};
use ark_std::log2;

/// Polynomial addition over finite fields
pub fn add<E: Field>(p1: &[E], p2: &[E]) -> Vec<E> {
    let mut result = vec![E::ZERO; std::cmp::max(p1.len(), p2.len())];

    for (i, &coeff) in p1.iter().enumerate() {
        result[i] += coeff;
    }
    for (i, &coeff) in p2.iter().enumerate() {
        result[i] += coeff;
    }

    result
}

/// Polynomial multiplication over finite fields
pub fn mul<E: Field>(p1: &[E], p2: &[E]) -> Vec<E> {
    if p1.is_empty() || p2.is_empty() {
        return vec![];
    }

    let mut result = vec![E::ZERO; p1.len() + p2.len() - 1];

    for (i, &coeff1) in p1.iter().enumerate() {
        for (j, &coeff2) in p2.iter().enumerate() {
            result[i + j] += coeff1 * coeff2;
        }
    }

    result
}

/// Polynomial division over finite fields
/// Returns the quotient of p1 / p2
pub fn div<E: Field>(p1: &[E], p2: &[E]) -> Result<Vec<E>, &'static str> {
    if p2.is_empty() || p2.iter().all(|&x| x == E::ZERO) {
        return Err("Cannot divide by zero polynomial");
    }

    if p1.len() < p2.len() {
        return Ok(vec![E::ZERO]);
    }

    let mut quotient = vec![E::ZERO; p1.len() - p2.len() + 1];
    let mut remainder: Vec<E> = p1.to_vec();

    while remainder.len() >= p2.len() {
        let leading_coeff = *remainder.last().unwrap();
        let divisor_leading = *p2.last().unwrap();
        
        if divisor_leading == E::ZERO {
            return Err("Leading coefficient of divisor is zero");
        }

        let coeff = leading_coeff * divisor_leading.inverse().unwrap();
        let pos = remainder.len() - p2.len();

        quotient[pos] = coeff;

        for (i, &factor) in p2.iter().enumerate() {
            remainder[pos + i] -= factor * coeff;
        }

        // Remove leading zeros
        while remainder.last() == Some(&E::ZERO) {
            remainder.pop();
        }

        if remainder.is_empty() {
            break;
        }
    }

    Ok(quotient)
}

/// Evaluate polynomial at a given point using Horner's method
pub fn evaluate<E: Field>(poly: &[E], point: E) -> E {
    if poly.is_empty() {
        return E::ZERO;
    }

    // Use Horner's method for efficient evaluation
    poly.iter().rev().fold(E::ZERO, |acc, &coeff| acc * point + coeff)
}

/// Lagrange interpolation given points and values
/// Reconstructs the unique polynomial of degree < n passing through all points
pub fn interpolate<E: Field>(points: &[E], values: &[E]) -> Result<Vec<E>, &'static str> {
    if points.len() != values.len() {
        return Err("Number of points and values must match");
    }

    if points.is_empty() {
        return Ok(vec![]);
    }

    // Check for duplicate points
    for i in 0..points.len() {
        for j in i + 1..points.len() {
            if points[i] == points[j] {
                return Err("Duplicate points not allowed in interpolation");
            }
        }
    }

    let mut result = vec![E::ZERO; points.len()];

    for i in 0..points.len() {
        let mut numerator = vec![E::ONE];
        let mut denominator = E::ONE;

        for j in 0..points.len() {
            if i == j {
                continue;
            }

            numerator = mul(&numerator, &[-points[j], E::ONE]);
            denominator *= points[i] - points[j];
        }

        if denominator == E::ZERO {
            return Err("Denominator is zero in Lagrange interpolation");
        }

        let denominator_inv = denominator.inverse().unwrap();
        let term: Vec<E> = numerator.iter()
            .map(|&x| x * values[i] * denominator_inv)
            .collect();

        result = add(&result, &term);
    }

    Ok(result)
}

/// Compute primitive root of unity for polynomial operations
pub fn get_omega<E: PrimeField>(coefficients: &[E]) -> E {
    let mut coefficients = coefficients.to_vec();
    let n = coefficients.len() - 1;
    if !n.is_power_of_two() {
        let num_coeffs = coefficients.len().checked_next_power_of_two().unwrap();
        // pad the coefficients with zeros to the nearest power of two
        for i in coefficients.len()..num_coeffs {
            coefficients.push(E::ZERO);
        }
    }

    let m = coefficients.len();
    let exp = log2(m);
    let mut omega = E::TWO_ADIC_ROOT_OF_UNITY;
    for _ in exp..E::TWO_ADICITY {
        omega.square_in_place();
    }
    omega
}

/// Multiply polynomial by scalar value
pub fn scalar_mul<E: Field>(poly: &[E], scalar: E) -> Vec<E> {
    poly.iter().map(|&coeff| coeff * scalar).collect()
}

/// Remove leading zero coefficients from polynomial
pub fn trim_zeros<E: Field>(poly: &[E]) -> Vec<E> {
    let mut result = poly.to_vec();
    while result.last() == Some(&E::ZERO) && result.len() > 1 {
        result.pop();
    }
    result
}

/// Compute polynomial degree (highest non-zero coefficient index)
pub fn degree<E: Field>(poly: &[E]) -> Option<usize> {
    for (i, &coeff) in poly.iter().enumerate().rev() {
        if coeff != E::ZERO {
            return Some(i);
        }
    }
    None
}
