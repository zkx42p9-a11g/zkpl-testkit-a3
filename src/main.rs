/// zkExp Zero-Knowledge Exponentiation Proof System
/// 
/// This module provides the main entry point for the zkExp benchmark suite,
/// implementing zero-knowledge proofs for discrete exponentiation with constant
/// verification time and proof size. The system supports multiple evaluation modes
/// including single exponentiations, batch processing, and comparative analysis.
///
/// Features:
/// - Constant-time verification independent of batch size
/// - Memory-optimized sliding window processing
/// - Comprehensive benchmarking against classical schemes
/// - Performance metrics collection and analysis
///
/// Based on the zkExp protocol using KZG polynomial commitments over BLS12-381.

// Core module dependencies
mod kzg;
mod asvc;
mod utils;
mod benchmark;
mod metrics;
mod zk_exp_lib;

// Benchmark and analysis modules
mod benchmark_runner;
mod single_exp_analysis;
mod backing_test;

// Baseline comparison modules (feature-gated)
#[cfg(feature = "schnorr-baseline")]
pub mod schnorr_baseline;
#[cfg(feature = "bls-baseline")]
pub mod bls_baseline;
#[cfg(feature = "groth16-baseline")]
pub mod groth16_baseline;

// Import dependencies
use crate::zk_exp_lib::*;
use benchmark_runner::run_comprehensive_comparison;
use std::env;

/// Main entry point for the zkExp benchmark suite
fn main() {
    println!("zkExp Zero-Knowledge Exponentiation Proof System");
    println!("================================================");
    
    let args: Vec<String> = env::args().collect();
    let mode = if args.len() > 1 { &args[1] } else { "comprehensive" };
    
    match mode {
        "zkexp" => {
            println!("\n=== zkExp Protocol Validation ===");
            validate_sliding_windows();
        }
        "baselines" => {
            println!("\n=== Baseline Comparisons ===");
            run_comprehensive_comparison();
        }
        "comparison" => {
            println!("\n=== zkExp + Baseline Analysis ===");
            validate_sliding_windows();
            run_comprehensive_comparison();
        }
        "single-analysis" => {
            println!("\n=== Single Exponentiation Analysis ===");
            single_exp_analysis::run_single_exponentiation_analysis();
        }
        "backing-test" => {
            println!("\n=== Backing Tests vs Traditional Methods ===");
            backing_test::run_backing_test_suite();
        }
        "backing-quick" => {
            println!("\n=== Quick Validation Test ===");
            quick_backing_validation();
        }
        _ => {
            println!("\n=== Comprehensive Benchmark Suite ===");
            validate_sliding_windows();
            run_comprehensive_comparison();
        }
    }
    
    println!("\n=== Benchmark Complete ===");
    display_usage_info();
}

/// Execute comprehensive sliding window validation
pub fn validate_sliding_windows() {
    println!("Starting sliding window validation...");
    
    let mut system = ZkExpSystem::new(4096, true, "sliding_window_validation");
    system.run_comprehensive_sliding_window_validation();
    
    println!("Extended batch size testing...");
    test_extended_batch_sizes(&mut system);
    
    println!("Sliding window validation complete.");
}

/// Test extended batch sizes for scalability analysis
fn test_extended_batch_sizes(system: &mut ZkExpSystem) {
    let test_cases = vec![
        (2000, 256, 64, "Extended_2000x256_w64"),
        (5000, 512, 128, "Extended_5000x512_w128"),
        (10000, 256, 32, "Extended_10000x256_w32"),
    ];
    
    for (batch_size, exponent_bits, window_size, test_name) in test_cases {
        println!("Testing {}: {} exponentiations with {}-bit exponents", 
                 test_name, batch_size, exponent_bits);
        
        let bases: Vec<_> = (0..batch_size)
            .map(|i| ark_bls12_381::Fr::from((i % 97 + 2) as u64))
            .collect();
            
        let exponents: Vec<_> = (0..batch_size)
            .map(|_| generate_realistic_exponent_bits(exponent_bits))
            .collect();
        
        let prove_start = std::time::Instant::now();
        match system.prove_sliding_window_batch(&bases, &exponents, window_size) {
            Ok(proof) => {
                let prove_time = prove_start.elapsed();
                
                let verify_start = std::time::Instant::now();
                let expected_results: Vec<_> = bases.iter()
                    .zip(exponents.iter())
                    .map(|(&base, exp_bits)| system.compute_exponentiation(base, exp_bits))
                    .collect();
                    
                let verified = system.verify_sliding_window_batch(
                    &proof, &bases, &exponents, &expected_results
                );
                let verify_time = verify_start.elapsed();
                
                let per_proof_us = prove_time.as_micros() as u64 / batch_size as u64;
                let throughput = batch_size as f64 / prove_time.as_secs_f64();
                
                println!("  ✓ {}: {:.2}ms total, {}μs per-proof, {:.1} ops/sec, {}ms verify, {} bytes", 
                         test_name,
                         prove_time.as_millis(),
                         per_proof_us,
                         throughput,
                         verify_time.as_millis(),
                         proof.size_bytes());
                         
                if !verified {
                    println!("  ⚠️  Verification failed!");
                }
            }
            Err(e) => println!("  ✗ {}: {}", test_name, e),
        }
    }
}

/// Execute quick backing test validation
fn quick_backing_validation() {
    use crate::backing_test::BackingTestSuite;
    use crate::zk_exp_lib::TestField;
    
    println!("Running quick validation test...");
    
    let mut suite = BackingTestSuite::new();
    let exponent_bits = vec![true, false, true, true]; // 13 = 1101₂
    
    match suite.compare_single_exponentiation(
        TestField::from(2u64),
        &exponent_bits,
        4,
        "QuickValidation"
    ) {
        Ok(result) => {
            println!("✅ Quick validation PASSED:");
            println!("   Correctness match: {}", result.correctness_match);
            println!("   zkExp verification: {}", result.zkexp_verification_success);
            println!("   Prove overhead: {:.1}x", result.prove_overhead_factor);
            println!("   Verify speedup: {:.1}x", result.verification_speedup);
            
            if result.correctness_match && result.zkexp_verification_success {
                println!("   🎉 Validation successful!");
            } else {
                println!("   ⚠️  Issues detected in validation");
            }
        }
        Err(e) => {
            println!("❌ Quick validation FAILED: {}", e);
        }
    }
}

/// Generate realistic exponent bit patterns for testing
fn generate_realistic_exponent_bits(bit_length: usize) -> Vec<bool> {
    (0..bit_length).map(|i| (i * 7 + 3) % 13 < 6).collect()
}

/// Display usage information and available modes
fn display_usage_info() {
    println!("\nAvailable execution modes:");
    println!("  cargo run zkexp               - zkExp validation only");
    println!("  cargo run baselines           - Baseline comparisons");
    println!("  cargo run comparison          - zkExp + baselines");
    println!("  cargo run single-analysis     - Single exponentiation analysis");
    println!("  cargo run backing-test        - Validation vs traditional methods");
    println!("  cargo run backing-quick       - Quick validation test");
    println!("  cargo run                     - Comprehensive benchmarks");
    
    println!("\nTo enable baseline features:");
    println!("  cargo run baselines --features schnorr-baseline");
    println!("  cargo run baselines --features all-baselines");
}
