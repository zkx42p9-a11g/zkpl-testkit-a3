/// Ed25519-Schnorr Baseline Implementation for zkExp Comparative Analysis
///
/// This module provides a high-quality Ed25519-Schnorr signature scheme implementation
/// for empirical comparison with the zkExp protocol. The implementation follows RFC 8032
/// standards and serves as a baseline for discrete logarithm-based signatures.
///
/// Key Characteristics:
/// - Ed25519 elliptic curve (Curve25519 in Edwards form)
/// - 128-bit security level with efficient curve arithmetic
/// - Individual signature verification (no batch optimization available)
/// - Linear verification complexity O(n) inherent to the scheme
/// - Compact signatures (64 bytes) with fast verification

use std::collections::HashMap;

#[cfg(feature = "schnorr-baseline")]
use {
    ed25519_dalek::{SigningKey, Signature, Signer, Verifier, VerifyingKey},
    std::time::Instant,
    rand::rngs::OsRng,
    rand::RngCore,
    rayon::prelude::*,
};

/// Comprehensive Ed25519-Schnorr benchmarking framework for zkExp comparative analysis
/// 
/// Implements systematic performance evaluation of Ed25519 signature verification
/// across multiple batch sizes to establish empirical baselines for comparison
/// with zkExp's constant-time verification claims.
#[cfg(feature = "schnorr-baseline")]
pub struct SchnorrBenchmark {
    pub signing_keys: Vec<SigningKey>,
    pub verifying_keys: Vec<VerifyingKey>,
    pub messages: Vec<Vec<u8>>,
    pub signatures: Vec<Signature>,
    pub batch_size: usize,
}

#[cfg(feature = "schnorr-baseline")]
impl SchnorrBenchmark {
    /// Initialize Ed25519-Schnorr benchmark with optimized setup
    pub fn setup(batch_size: usize) -> Self {
        let setup_start = Instant::now();
        
        if batch_size >= 100 {
            println!("Ed25519-Schnorr benchmark setup: {} signatures", batch_size);
        }
        
        let mut signing_keys = Vec::with_capacity(batch_size);
        let mut verifying_keys = Vec::with_capacity(batch_size);
        let mut messages = Vec::with_capacity(batch_size);
        let mut signatures = Vec::with_capacity(batch_size);

        // Generate keypairs, messages, and signatures
        for i in 0..batch_size {
            // Generate cryptographically secure Ed25519 keypair
            let mut secret_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut secret_bytes);
            let signing_key = SigningKey::from_bytes(&secret_bytes);
            let verifying_key = signing_key.verifying_key();
            
            // Generate unique message for comparative analysis
            let message = format!("zkExp comparative analysis message {}", i).into_bytes();
            
            // Generate signature following RFC 8032 specification
            let signature = signing_key.sign(&message);
            
            signing_keys.push(signing_key);
            verifying_keys.push(verifying_key);
            messages.push(message);
            signatures.push(signature);
        }

        let setup_time = setup_start.elapsed();
        
        if batch_size >= 100 {
            println!("Setup completed in {:.2}ms", setup_time.as_millis());
        }

        Self { 
            signing_keys, 
            verifying_keys,
            messages, 
            signatures,
            batch_size,
        }
    }

    /// Individual signature verification following RFC 8032 specification
    /// 
    /// Performs standard Ed25519 signature verification for each signature
    /// independently. This represents the fundamental O(n) verification complexity
    /// inherent to Ed25519.
    pub fn verify_individual(&self) -> (bool, u128) {
        let start = Instant::now();
        
        let mut all_valid = true;
        for i in 0..self.batch_size {
            if self.verifying_keys[i].verify(&self.messages[i], &self.signatures[i]).is_err() {
                all_valid = false;
                break; // Early termination on verification failure
            }
        }
        
        (all_valid, start.elapsed().as_micros())
    }

    /// Optimized individual verification using iterator chains
    pub fn verify_batch_optimized(&self) -> (bool, u128) {
        let start = Instant::now();
        
        let all_valid = self.verifying_keys.iter()
            .zip(&self.messages)
            .zip(&self.signatures)
            .all(|((vkey, msg), sig)| vkey.verify(msg, sig).is_ok());
        
        (all_valid, start.elapsed().as_micros())
    }

    /// Parallel verification attempt for large batches
    pub fn verify_parallel(&self) -> (bool, u128) {
        let start = Instant::now();
        
        // Use parallel verification for batches > 50 to optimize constant factors
        let all_valid = if self.batch_size > 50 {
            (0..self.batch_size)
                .into_par_iter()
                .all(|i| self.verifying_keys[i].verify(&self.messages[i], &self.signatures[i]).is_ok())
        } else {
            // Sequential for smaller batches to avoid parallelization overhead
            self.verifying_keys.iter()
                .zip(&self.messages)
                .zip(&self.signatures)
                .all(|((vkey, msg), sig)| vkey.verify(msg, sig).is_ok())
        };
        
        (all_valid, start.elapsed().as_micros())
    }

    /// Demonstrate Ed25519's lack of native batch verification
    pub fn verify_batch_naive(&self) -> (bool, u128) {
        // Ed25519 has no native batch verification - must verify individually
        self.verify_individual()
    }

    /// Benchmark raw Ed25519 signing operations
    pub fn bench_signing(batch_size: usize) -> u128 {
        let mut rng = OsRng;
        
        // Pre-generate signing keys
        let signing_keys: Vec<SigningKey> = (0..batch_size)
            .map(|_| {
                let mut secret_bytes = [0u8; 32];
                rng.fill_bytes(&mut secret_bytes);
                SigningKey::from_bytes(&secret_bytes)
            })
            .collect();
        
        // Pre-generate messages
        let messages: Vec<Vec<u8>> = (0..batch_size)
            .map(|i| format!("performance benchmark message {}", i).into_bytes())
            .collect();
        
        // Measure signing performance
        let start = Instant::now();
        let _signatures: Vec<Signature> = signing_keys.iter()
            .zip(&messages)
            .map(|(key, msg)| key.sign(msg))
            .collect();
        
        start.elapsed().as_micros()
    }

    /// Benchmark Ed25519 key generation performance
    pub fn bench_key_generation(num_keys: usize) -> u128 {
        let mut rng = OsRng;
        
        let start = Instant::now();
        let _keys: Vec<SigningKey> = (0..num_keys)
            .map(|_| {
                let mut secret_bytes = [0u8; 32];
                rng.fill_bytes(&mut secret_bytes);
                SigningKey::from_bytes(&secret_bytes)
            })
            .collect();
        
        start.elapsed().as_micros()
    }

    /// Comprehensive performance analysis for comparative evaluation
    pub fn performance_analysis(&self) -> HashMap<String, u128> {
        let mut metrics = HashMap::new();

        // Individual verification analysis
        let (_, individual_time) = self.verify_individual();
        metrics.insert("individual_verification_us".to_string(), individual_time);
        metrics.insert("individual_per_sig_us".to_string(), individual_time / self.batch_size as u128);

        // Optimized iterator-based verification
        let (_, batch_optimized_time) = self.verify_batch_optimized();
        metrics.insert("batch_optimized_verification_us".to_string(), batch_optimized_time);

        // Parallel verification for large batches
        let (_, parallel_time) = self.verify_parallel();
        metrics.insert("parallel_verification_us".to_string(), parallel_time);

        // Demonstrate lack of batch verification benefits
        let (_, naive_batch_time) = self.verify_batch_naive();
        metrics.insert("naive_batch_verification_us".to_string(), naive_batch_time);

        // Raw cryptographic operation benchmarks
        let signing_time = Self::bench_signing(self.batch_size);
        metrics.insert("signing_us".to_string(), signing_time);

        let keygen_time = Self::bench_key_generation(self.batch_size);
        metrics.insert("key_generation_us".to_string(), keygen_time);

        // Throughput calculations
        if individual_time > 0 {
            let signatures_per_second = (self.batch_size as u128 * 1_000_000) / individual_time;
            metrics.insert("verification_ops_per_sec".to_string(), signatures_per_second);
        }

        // Efficiency ratios
        if individual_time > 0 {
            let parallel_speedup = individual_time as f64 / parallel_time.max(1) as f64;
            metrics.insert("parallel_speedup_factor".to_string(), (parallel_speedup * 100.0) as u128);
        }

        metrics
    }

    /// Generate benchmark summary
    pub fn generate_report(&self) -> String {
        let metrics = self.performance_analysis();
        let mut report = String::new();
        
        report.push_str(&format!("\n=== Ed25519-Schnorr Performance Analysis ===\n"));
        report.push_str(&format!("Protocol: Ed25519 Digital Signature Algorithm (RFC 8032)\n"));
        report.push_str(&format!("Batch size: {} signatures\n\n", self.batch_size));

        if let Some(&time) = metrics.get("individual_verification_us") {
            let per_sig_time = time as f64 / self.batch_size as f64;
            report.push_str(&format!("Individual verification: {:.2}ms ({:.1}μs per signature)\n", 
                time as f64 / 1000.0, per_sig_time));
        }
        
        if let Some(&time) = metrics.get("parallel_verification_us") {
            report.push_str(&format!("Parallel verification: {:.2}ms\n", time as f64 / 1000.0));
            
            if let Some(&speedup) = metrics.get("parallel_speedup_factor") {
                report.push_str(&format!("Parallel speedup: {:.1}x\n", speedup as f64 / 100.0));
            }
        }

        if let Some(&ops_per_sec) = metrics.get("verification_ops_per_sec") {
            report.push_str(&format!("Throughput: {} signatures/second\n", ops_per_sec));
        }

        report.push_str(&format!("\nSignature characteristics:\n"));
        report.push_str(&format!("  Size per signature: 64 bytes\n"));
        report.push_str(&format!("  Total batch size: {} bytes\n", self.batch_size * 64));
        report.push_str(&format!("  Complexity: O(n) - linear scaling\n"));

        report.push_str(&format!("\nKey limitations:\n"));
        report.push_str("  • No native batch verification capability\n");
        report.push_str("  • Each signature requires independent verification\n");
        report.push_str("  • Linear verification time scaling\n");

        report
    }

    /// Protocol identifier
    pub fn scheme_name() -> &'static str {
        "Ed25519-Schnorr (RFC 8032)"
    }
}

/// Disabled module implementation for optional compilation
#[cfg(not(feature = "schnorr-baseline"))]
pub struct SchnorrBenchmark;

#[cfg(not(feature = "schnorr-baseline"))]
impl SchnorrBenchmark {
    pub fn setup(_batch_size: usize) -> Self {
        panic!("Ed25519-Schnorr baseline requires --features schnorr-baseline");
    }
    
    pub fn verify_individual(&self) -> (bool, u128) {
        panic!("Schnorr baseline not available - enable with --features schnorr-baseline");
    }
    
    pub fn verify_batch_optimized(&self) -> (bool, u128) {
        panic!("Schnorr baseline not available - enable with --features schnorr-baseline");
    }
    
    pub fn verify_parallel(&self) -> (bool, u128) {
        panic!("Schnorr baseline not available - enable with --features schnorr-baseline");
    }
    
    pub fn verify_batch_naive(&self) -> (bool, u128) {
        panic!("Schnorr baseline not available - enable with --features schnorr-baseline");
    }

    pub fn performance_analysis(&self) -> HashMap<String, u128> {
        panic!("Schnorr baseline not available - enable with --features schnorr-baseline");
    }

    pub fn generate_report(&self) -> String {
        "Ed25519-Schnorr baseline disabled - enable with --features schnorr-baseline".to_string()
    }

    pub fn scheme_name() -> &'static str {
        "Ed25519-Schnorr (disabled - requires feature flag)"
    }
}

// === Integration Functions ===

/// Comprehensive Ed25519-Schnorr baseline analysis
#[cfg(feature = "schnorr-baseline")]
pub fn run_comprehensive_schnorr_analysis(batch_sizes: &[usize]) -> Result<Vec<SchnorrBenchmark>, String> {
    println!("=== Ed25519-Schnorr Baseline Analysis ===");
    println!("Testing linear verification complexity across batch sizes\n");
    
    let mut benchmarks = Vec::new();
    
    for &batch_size in batch_sizes {
        println!("Testing batch size: {}", batch_size);
        
        let benchmark = SchnorrBenchmark::setup(batch_size);
        let metrics = benchmark.performance_analysis();
        
        if let Some(&individual_time) = metrics.get("individual_verification_us") {
            let per_sig_us = individual_time as f64 / batch_size as f64;
            println!("  Verification: {:.2}ms ({:.1}μs per signature)", 
                    individual_time as f64 / 1000.0, per_sig_us);
        }
        
        if let Some(&ops_per_sec) = metrics.get("verification_ops_per_sec") {
            println!("  Throughput: {} ops/sec", ops_per_sec);
        }
        
        println!("  Storage: {} KB", (batch_size * 64) / 1024);
        
        benchmarks.push(benchmark);
    }
    
    println!("\n✓ Ed25519-Schnorr analysis completed");
    Ok(benchmarks)
}

/// Quick Ed25519-Schnorr validation
#[cfg(feature = "schnorr-baseline")]
pub fn quick_schnorr_validation() -> Result<String, String> {
    println!("=== Quick Ed25519-Schnorr Validation ===");
    
    let benchmark = SchnorrBenchmark::setup(10);
    
    let (individual_valid, individual_time) = benchmark.verify_individual();
    let (parallel_valid, parallel_time) = benchmark.verify_parallel();
    
    if individual_valid && parallel_valid {
        Ok(format!(
            "Ed25519-Schnorr validation successful: Individual {}μs, Parallel {}μs",
            individual_time, parallel_time
        ))
    } else {
        Err("Ed25519-Schnorr validation failed".to_string())
    }
}

/// Export performance data for analysis
#[cfg(feature = "schnorr-baseline")]
pub fn export_schnorr_performance_data(batch_sizes: &[usize], filename: &str) -> Result<(), String> {
    let mut content = String::new();
    content.push_str("batch_size,individual_verification_us,parallel_verification_us,per_sig_us,ops_per_sec,total_size_bytes\n");
    
    for &batch_size in batch_sizes {
        let benchmark = SchnorrBenchmark::setup(batch_size);
        let metrics = benchmark.performance_analysis();
        
        let individual_time = metrics.get("individual_verification_us").unwrap_or(&0);
        let parallel_time = metrics.get("parallel_verification_us").unwrap_or(&0);
        let per_sig_time = metrics.get("individual_per_sig_us").unwrap_or(&0);
        let ops_per_sec = metrics.get("verification_ops_per_sec").unwrap_or(&0);
        
        content.push_str(&format!("{},{},{},{},{},{}\n",
            batch_size,
            individual_time,
            parallel_time,
            per_sig_time,
            ops_per_sec,
            64 * batch_size
        ));
    }
    
    std::fs::write(filename, content)
        .map_err(|e| format!("Failed to export data: {}", e))?;
    
    println!("Performance data exported to: {}", filename);
    Ok(())
}

// === Disabled Function Implementations ===

#[cfg(not(feature = "schnorr-baseline"))]
pub fn run_comprehensive_schnorr_analysis(_batch_sizes: &[usize]) -> Result<Vec<SchnorrBenchmark>, String> {
    Err("Ed25519-Schnorr analysis requires --features schnorr-baseline".to_string())
}

#[cfg(not(feature = "schnorr-baseline"))]
pub fn quick_schnorr_validation() -> Result<String, String> {
    Err("Ed25519-Schnorr validation requires --features schnorr-baseline".to_string())
}

#[cfg(not(feature = "schnorr-baseline"))]
pub fn export_schnorr_performance_data(_batch_sizes: &[usize], _filename: &str) -> Result<(), String> {
    Err("Ed25519-Schnorr data export requires --features schnorr-baseline".to_string())
}

// === Unit Tests ===

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(feature = "schnorr-baseline")]
    #[test]
    fn test_schnorr_basic_functionality() {
        let benchmark = SchnorrBenchmark::setup(5);
        
        let (valid, _time) = benchmark.verify_individual();
        assert!(valid, "Individual verification should succeed");
        
        let (valid, _time) = benchmark.verify_batch_optimized();
        assert!(valid, "Optimized verification should succeed");
        
        let (valid, _time) = benchmark.verify_parallel();
        assert!(valid, "Parallel verification should succeed");
    }
    
    #[cfg(feature = "schnorr-baseline")]
    #[test]
    fn test_schnorr_performance_scaling() {
        let small_benchmark = SchnorrBenchmark::setup(10);
        let large_benchmark = SchnorrBenchmark::setup(100);
        
        let small_metrics = small_benchmark.performance_analysis();
        let large_metrics = large_benchmark.performance_analysis();
        
        let small_time = small_metrics.get("individual_verification_us").unwrap_or(&1);
        let large_time = large_metrics.get("individual_verification_us").unwrap_or(&1);
        
        let scaling_factor = *large_time as f64 / *small_time as f64;
        
        // Should scale roughly 10x for 10x more signatures
        assert!(scaling_factor > 5.0 && scaling_factor < 20.0, 
               "Scaling factor {} outside expected range", scaling_factor);
    }
    
    #[cfg(feature = "schnorr-baseline")]
    #[test]
    fn test_schnorr_signature_correctness() {
        use rand::rngs::OsRng;
        
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        
        let message = b"test message";
        let signature = signing_key.sign(message);
        
        assert!(verifying_key.verify(message, &signature).is_ok(), "Valid signature should verify");
        
        let wrong_message = b"wrong message";
        assert!(verifying_key.verify(wrong_message, &signature).is_err(), "Invalid signature should not verify");
    }
    
    #[test]
    fn test_schnorr_disabled_functionality() {
        #[cfg(not(feature = "schnorr-baseline"))]
        {
            let result = std::panic::catch_unwind(|| {
                SchnorrBenchmark::setup(5)
            });
            assert!(result.is_err(), "Disabled Schnorr should panic");
        }
    }
}
