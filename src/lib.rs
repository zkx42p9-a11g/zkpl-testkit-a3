#![warn(clippy::all)]

/// zkExp: Zero-Knowledge Exponentiation Proof System
///
/// A high-performance implementation of zero-knowledge proofs for discrete exponentiation
/// with constant verification time and proof size. Built on KZG polynomial commitments
/// over BLS12-381 curves with 128-bit security.
///
/// # Features
/// 
/// - **Constant verification**: O(1) verification time independent of batch size
/// - **Compact proofs**: 256-byte proofs for any number of exponentiations
/// - **Memory efficient**: Sliding window optimization for large batches
/// - **Benchmarking suite**: Comprehensive performance analysis tools
///
/// # Architecture
///
/// The library is organized into several key modules:
/// - [`kzg`]: KZG polynomial commitment implementation
/// - [`utils`]: Polynomial arithmetic utilities  
/// - [`metrics`]: Performance measurement and analysis
/// - [`benchmark_runner`]: Comparative benchmarking tools

// Core cryptographic modules
mod kzg;
mod asvc;
mod utils;

// Zero-knowledge proof system
mod zk_exp_lib;

// Performance analysis
mod metrics;
mod benchmark;

// Benchmarking infrastructure
pub mod benchmark_runner;

// Analysis modules
mod single_exp_analysis;
mod backing_test;

// Optional baseline comparison modules
#[cfg(feature = "schnorr-baseline")]
pub mod schnorr_baseline;

#[cfg(feature = "bls-baseline")]
pub mod bls_baseline;


// Re-export main types and functions for public API
pub use zk_exp_lib::{
    ZkExpSystem,
    TestField,
};

pub use metrics::{
    ZKProofMetrics,
    MetricsCollector,
    ProtocolSummary,
    BenchmarkAggregator,
};

pub use benchmark_runner::run_comprehensive_comparison;
