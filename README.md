# zkExp: Zero-Knowledge Succinct Exponentiation Proofs

**The first zero-knowledge proof system achieving O(1) verification for batched exponentiation**

## Overview

zkExp is a novel zero-knowledge proof system for verifying discrete exponentiation statements `y_i = g^{x_i}` without revealing secret exponents. Our protocol overcomes linear scaling limitations by achieving:

- **O(1) verification time** (constant 3.5ms regardless of batch size)
- **Constant proof size** (256 bytes for arbitrary batches)  
- **Õ(kℓ) prover time** for k exponentiations of ℓ-bit exponents
- **Memory-efficient** sliding window optimization (O(√ℓ) memory)

## Key Innovations

1. **Trace-based encoding** - Polynomial representation of square-and-multiply computation
2. **Lazy sumcheck protocols** - Degree-preserving constraint verification  
3. **Hybrid FFT decomposition** - Memory-conscious polynomial operations
4. **Sliding-window batching** - Single-proof aggregation via KZG commitments

## Performance Highlights

| Metric                      | Single (4096-bit) | Batch (1000×128-bit) |
|-----------------------------|-------------------|----------------------|
| Verification Time           | 3.5 ms            | 3.63 ms              |
| Proof Size                  | 256 bytes         | 256 bytes            |
| Prover Overhead             | 16.3×             | 1.35× (87× vs single)|
| Memory Usage                | 1.11 MB           | 1.07 MB              |
| Ethereum Gas (1000 ops)     | -                 | 267k gas             |

## Installation

```bash
git clone https://github.com/zkexp-team/zkexp
cd zkexp
cargo build --release
```

**System Requirements:**
- Rust 1.75+
- 128GB RAM recommended for full benchmarks

## Usage

### Single Exponentiation Proof

```rust
use zkexp::{ZkExpSystem, TestField};

let mut system = ZkExpSystem::new(1024, false, "demo");
let base = TestField::from(2u64);
let exponent = vec![true, false, true, true]; // 13 in binary LSB-first

let proof = system.prove_single_exponentiation(base, &exponent)?;
let result = system.compute_exponentiation(base, &exponent);

assert!(system.verify_single_exponentiation(&proof, base, &exponent, result));
```

### Batch Exponentiation Proof

```rust
let bases = vec![TestField::from(2u64), TestField::from(3u64), TestField::from(5u64)];
let exponents = vec![
    vec![true, false, true, true],   // 13
    vec![false, true, false, true],  // 10  
    vec![true, true, true, false],   // 7
];

let proof = system.prove_sliding_window_batch(&bases, &exponents, 2)?;

let results: Vec<_> = bases.iter()
    .zip(exponents.iter())
    .map(|(&base, exp)| system.compute_exponentiation(base, exp))
    .collect();

assert!(system.verify_sliding_window_batch(&proof, &bases, &exponents, &results));
```

## Benchmarking

```bash
# Full benchmark suite
RUSTFLAGS="-C target-cpu=native -C target-feature=+avx2,+fma" cargo run --release --features full

# zkExp protocol validation
RUSTFLAGS="-C target-cpu=native -C target-feature=+avx2,+fma" cargo run --release zkexp

# Baseline comparisons
RUSTFLAGS="-C target-cpu=native -C target-feature=+avx2,+fma" cargo run --release --features all-baselines baselines

# Single exponentiation analysis  
RUSTFLAGS="-C target-cpu=native -C target-feature=+avx2,+fma" cargo run --release single-analysis

# Quick validation
RUSTFLAGS="-C target-cpu=native -C target-feature=+avx2,+fma" cargo run --release backing-quick
```

## Features

**Core Features:**
- `plotting` - Performance visualization
- `benchmarking` - Comprehensive benchmark suite

**Baseline Comparisons:**
- `schnorr-baseline` - Ed25519 Schnorr signatures
- `bls-baseline` - BLS12-381 signature aggregation
- `groth16-baseline` - Groth16 SNARK comparison
- `all-baselines` - Enable all baseline comparisons

**Utility Features:**
- `perf-monitoring` - Hardware performance counters
- `fast-allocator` - Optimized memory allocation
- `full` - Complete feature set

## Cryptographic Foundations

- **Security**: (q,ℓ)-GDHE assumption with 128-bit security
- **Curve**: BLS12-381 with 255-bit scalar field
- **Commitments**: KZG polynomial commitments
- **Fiat-Shamir**: Domain-separated SHA-256 transformations
- **Zero-Knowledge**: Perfect zero-knowledge in standard model

## Repository Structure

```
zkexp/
├── src/
│   ├── main.rs              # Main benchmark executable
│   ├── lib.rs               # Library interface and exports
│   ├── kzg.rs               # KZG polynomial commitment implementation
│   ├── asvc.rs              # Aggregatable vector commitments
│   ├── zk_exp_lib.rs        # Core zkExp protocol implementation
│   ├── utils.rs             # Polynomial arithmetic utilities
│   ├── metrics.rs           # Performance measurement framework
│   ├── benchmark_runner.rs  # Comprehensive benchmarking tools
│   ├── single_exp_analysis.rs # Individual exponentiation analysis
│   ├── backing_test.rs      # Validation test suite
│   ├── schnorr_baseline.rs  # Schnorr signature baseline (feature-gated)
│   └── bls_baseline.rs      # BLS signature baseline (feature-gated)
├── Cargo.toml              # Project configuration and dependencies
└── README.md               # This file
```

## Applications

zkExp enables practical deployment where linear verification costs are prohibitive:

- **Zero-knowledge rollups** - Constant verification regardless of transaction count
- **Anonymous credentials** - Privacy-preserving batch verification
- **Threshold cryptography** - Efficient multi-party computation verification
- **PKI systems** - Scalable certificate chain validation
- **IoT authentication** - Batch device verification

## Citation

```bibtex
@misc{zkexp2025,
  title={zkExp: Zero-Knowledge Succinct Exponentiation Proofs},
  author={Anonymous Submission},
  howpublished={IACR Communications in Cryptology},
  year={2025}
}
```

## Reproducibility

This implementation is provided for **peer review and reproducibility** purposes in support of our IACR Communications in Cryptology submission. The code enables reviewers to:

- Validate theoretical claims through empirical benchmarks
- Reproduce performance measurements from the manuscript
- Verify correctness of the zkExp protocol implementation
- Compare against baseline cryptographic schemes

**Research Use Only**: This code is intended solely for academic evaluation and research purposes during the peer review process.

---

**Note**: This implementation demonstrates the first asymptotically efficient bounds for zero-knowledge exponentiation proofs, enabling constant-time verification and constant-size proofs regardless of batch size.
