// src/benchmark_runner.rs - Comprehensive benchmark suite for zkExp performance evaluation
use std::collections::HashMap;
use std::time::Instant;
use std::fs::File;
use std::io::Write;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct BenchmarkResult {
    pub scheme: String,
    pub batch_size: usize,
    pub exponent_bits: usize,
    pub prove_time_us: u128,
    pub verify_time_us: u128,
    pub proof_size_bytes: usize,
    pub success: bool,
    pub throughput_ops_per_sec: f64,
    pub per_operation_us: f64,
    pub timestamp: DateTime<Utc>,
    pub memory_usage_mb: Option<f64>,
    pub scaling_efficiency: Option<f64>,
}

impl BenchmarkResult {
    pub fn new(scheme: &str, batch_size: usize, exponent_bits: usize, 
               prove_time_us: u128, verify_time_us: u128, proof_size_bytes: usize, success: bool) -> Self {
        
        // Calculate throughput metrics, handling edge cases for zero timing
        let (throughput_ops_per_sec, per_operation_us) = if prove_time_us > 0 {
            let throughput = (batch_size as f64) / (prove_time_us as f64 / 1_000_000.0);
            let per_op = prove_time_us as f64 / batch_size as f64;
            (throughput, per_op)
        } else {
            // For baseline schemes without prove time, use verify time for calculations
            let throughput = if verify_time_us > 0 {
                (batch_size as f64) / (verify_time_us as f64 / 1_000_000.0)
            } else {
                0.0
            };
            let per_op = if verify_time_us > 0 {
                verify_time_us as f64 / batch_size as f64
            } else {
                0.0
            };
            (throughput, per_op)
        };

        Self {
            scheme: scheme.to_string(),
            batch_size,
            exponent_bits,
            prove_time_us,
            verify_time_us,
            proof_size_bytes,
            success,
            throughput_ops_per_sec,
            per_operation_us,
            timestamp: Utc::now(),
            memory_usage_mb: None,
            scaling_efficiency: None,
        }
    }
    
    pub fn to_csv_row(&self) -> String {
        format!("{},{},{},{},{},{},{},{:.2},{:.4},{},{},{:.2}",
            self.scheme,
            self.batch_size,
            self.exponent_bits,
            self.prove_time_us,
            self.verify_time_us,
            self.proof_size_bytes,
            if self.success { "true" } else { "false" },
            self.throughput_ops_per_sec,
            self.per_operation_us,
            self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
            self.memory_usage_mb.unwrap_or(0.0),
            self.scaling_efficiency.unwrap_or(0.0)
        )
    }
}

pub struct ThroughputCeilingAnalysis {
    pub web3_scale_batches: Vec<usize>,
    pub exponent_sizes: Vec<usize>,
    pub results: Vec<BenchmarkResult>,
    pub output_file: String,
}

impl ThroughputCeilingAnalysis {
    pub fn new() -> Self {
        Self {
            // Large-scale batch sizes for testing system limits
            web3_scale_batches: vec![
                1_000,      // 1K operations - typical DeFi transactions
                5_000,      // 5K operations - medium-scale applications
                10_000,     // 10K operations - high-throughput applications
                25_000,     // 25K operations - exchange-level operations
                50_000,     // 50K operations - blockchain validation workloads
                100_000,    // 100K operations - enterprise-scale batches
                250_000,    // 250K operations - payment processing
                500_000,    // 500K operations - large-scale financial systems
                1_000_000,  // 1M operations - maximum scale testing
            ],
            exponent_sizes: vec![128, 256, 512, 1024],
            results: Vec::new(),
            output_file: format!("zkexp_throughput_analysis_{}.csv", 
                               Utc::now().format("%Y%m%d_%H%M%S")),
        }
    }
    
    pub fn run_ceiling_analysis(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== THROUGHPUT CEILING ANALYSIS ===");
        println!("Testing exponentially growing batches to validate O(1) verification scaling");
        println!("Output file: {}", self.output_file);
        
        self.initialize_csv_file()?;
        
        let web3_scale_batches = self.web3_scale_batches.clone();
        let exponent_sizes = self.exponent_sizes.clone();
        
        for exponent_bits in exponent_sizes {
            println!("\nTesting {}-bit exponents:", exponent_bits);
            
            for batch_size in &web3_scale_batches {
                println!("  Processing batch size: {} operations...", batch_size);
                
                // Test zkExp performance
                match self.measure_zkexp_batch(*batch_size, exponent_bits) {
                    Ok(mut result) => {
                        result.scaling_efficiency = self.calculate_scaling_efficiency(&result);
                        
                        println!("    zkExp: {:.2}ms prove, {:.2}ms verify, {:.1} ops/sec", 
                               result.prove_time_us as f64 / 1000.0,
                               result.verify_time_us as f64 / 1000.0,
                               result.throughput_ops_per_sec);
                        
                        self.save_result_to_csv(&result)?;
                        self.results.push(result);
                    }
                    Err(e) => {
                        println!("    Failed: {}", e);
                        let failed_result = BenchmarkResult::new(
                            "zkExp_failed", *batch_size, exponent_bits, 0, 0, 0, false
                        );
                        self.save_result_to_csv(&failed_result)?;
                    }
                }
                
                // Run baseline comparisons for manageable batch sizes
                if *batch_size <= 10_000 {
                    if let Err(e) = self.measure_baseline_comparison(*batch_size, exponent_bits) {
                        println!("    Baseline comparison failed: {}", e);
                    }
                }
            }
        }
        
        self.analyze_throughput_ceiling();
        self.generate_o1_proof_analysis();
        
        println!("\nThroughput ceiling analysis complete!");
        println!("Results saved to: {}", self.output_file);
        
        Ok(())
    }

    fn measure_zkexp_batch(&self, batch_size: usize, exponent_bits: usize) -> Result<BenchmarkResult, String> {
        // Initialize zkExp system with appropriate parameters
        let mut system = crate::zk_exp_lib::ZkExpSystem::new(
            exponent_bits.max(256), false, &format!("ceiling_analysis_{}_{}", batch_size, exponent_bits)
        );
        
        // Generate test data with realistic distribution
        let bases: Vec<crate::zk_exp_lib::TestField> = (0..batch_size)
            .map(|i| crate::zk_exp_lib::TestField::from((i % 97 + 2) as u64))
            .collect();
            
        let exponents: Vec<Vec<bool>> = (0..batch_size)
            .map(|_| self.generate_realistic_exponent_bits(exponent_bits))
            .collect();

        // Measure proving time
        let prove_start = Instant::now();
        let proof_result = system.prove_batch_exponentiations_with_metrics(
            &bases, &exponents, &format!("batch_{}", batch_size)
        );
        
        match proof_result {
            Ok((proof, _metrics)) => {
                let prove_time = prove_start.elapsed().as_micros();
                
                // Measure verification time
                let expected_results: Vec<_> = bases.iter()
                    .zip(exponents.iter())
                    .map(|(&base, exp_bits)| system.compute_exponentiation(base, exp_bits))
                    .collect();
                
                let verify_start = Instant::now();
                let verified = system.verify_batch_exponentiations(&proof, &bases, &exponents, &expected_results);
                let verify_time = verify_start.elapsed().as_micros();
                
                Ok(BenchmarkResult::new(
                    "zkExp",
                    batch_size,
                    exponent_bits,
                    prove_time,
                    verify_time,
                    proof.size_bytes(),
                    verified
                ))
            }
            Err(e) => Err(format!("zkExp proof failed: {}", e))
        }
    }
    
    fn measure_baseline_comparison(&mut self, batch_size: usize, exponent_bits: usize) -> Result<(), Box<dyn std::error::Error>> {
        // Measure actual baseline implementations
        let mut baseline_results = Vec::new();
        
        // Naive exponentiation baseline
        if let Ok(result) = self.measure_naive_exponentiation(batch_size, exponent_bits) {
            baseline_results.push(result);
        }
        
        // Schnorr signature baseline (if enabled)
        #[cfg(feature = "schnorr-baseline")]
        {
            if let Ok(result) = self.measure_schnorr_batch(batch_size, exponent_bits) {
                baseline_results.push(result);
            }
        }
        
        // BLS signature baselines (if enabled)
        #[cfg(feature = "bls-baseline")]
        {
            if let Ok(result) = self.measure_bls_individual(batch_size, exponent_bits) {
                baseline_results.push(result);
            }
            
            if let Ok(result) = self.measure_bls_aggregated(batch_size, exponent_bits) {
                baseline_results.push(result);
            }
        }
        
        // Save all baseline results
        for mut result in baseline_results {
            result.scaling_efficiency = self.calculate_scaling_efficiency(&result);
            self.save_result_to_csv(&result)?;
            self.results.push(result);
        }
        
        Ok(())
    }
    
    /// Measure naive exponentiation using field arithmetic
    fn measure_naive_exponentiation(&self, batch_size: usize, exponent_bits: usize) -> Result<BenchmarkResult, String> {
        use crate::zk_exp_lib::TestField;
        use ark_ff::{Field, One, Zero};
        
        // Generate test data
        let bases: Vec<TestField> = (0..batch_size)
            .map(|i| TestField::from((i % 97 + 2) as u64))
            .collect();
        
        // Generate manageable exponent values for performance testing
        let exponents: Vec<u64> = (0..batch_size)
            .map(|i| {
                let base_exp = std::cmp::min(exponent_bits, 32); // Limit for practical performance
                (1u64 << (base_exp / 4)) + (i as u64 % 1000)
            })
            .collect();
        
        // Measure naive exponentiation computation
        let prove_start = Instant::now();
        let results: Vec<TestField> = bases.iter().zip(exponents.iter())
            .map(|(&base, &exp)| {
                // Implement square-and-multiply exponentiation
                let mut result = TestField::one();
                let mut base_power = base;
                let mut exp_remaining = exp;
                
                while exp_remaining > 0 {
                    if exp_remaining & 1 == 1 {
                        result *= base_power;
                    }
                    base_power = base_power.square();
                    exp_remaining >>= 1;
                }
                
                result
            })
            .collect();
        let prove_time = prove_start.elapsed().as_micros();
        
        // Measure verification (recomputation and comparison)
        let verify_start = Instant::now();
        let mut all_correct = true;
        for (i, (&base, &exp)) in bases.iter().zip(exponents.iter()).enumerate() {
            let mut computed = TestField::one();
            let mut base_power = base;
            let mut exp_remaining = exp;
            
            while exp_remaining > 0 {
                if exp_remaining & 1 == 1 {
                    computed *= base_power;
                }
                base_power = base_power.square();
                exp_remaining >>= 1;
            }
            
            if computed != results[i] {
                all_correct = false;
                break;
            }
        }
        let verify_time = verify_start.elapsed().as_micros();
        
        Ok(BenchmarkResult::new(
            "Naive_Exponentiation",
            batch_size,
            exponent_bits,
            prove_time,
            verify_time,
            batch_size * 32, // Estimated result size
            all_correct
        ))
    }
    
    /// Measure Schnorr signature baseline performance
    #[cfg(feature = "schnorr-baseline")]
    fn measure_schnorr_batch(&self, batch_size: usize, exponent_bits: usize) -> Result<BenchmarkResult, String> {
        let prove_start = Instant::now();
        let schnorr = crate::schnorr_baseline::SchnorrBenchmark::setup(batch_size);
        let prove_time = prove_start.elapsed().as_micros();
        
        let verify_start = Instant::now();
        let (success, _) = schnorr.verify_individual();
        let verify_time = verify_start.elapsed().as_micros();
        
        Ok(BenchmarkResult::new(
            "Schnorr_Proofs",
            batch_size,
            exponent_bits,
            prove_time,
            verify_time,
            batch_size * 64, // Schnorr signature size
            success
        ))
    }
    
    #[cfg(not(feature = "schnorr-baseline"))]
    fn measure_schnorr_batch(&self, batch_size: usize, exponent_bits: usize) -> Result<BenchmarkResult, String> {
        Err("Schnorr baseline not enabled".to_string())
    }
    
    /// Measure BLS individual signature verification
    #[cfg(feature = "bls-baseline")]
    fn measure_bls_individual(&self, batch_size: usize, exponent_bits: usize) -> Result<BenchmarkResult, String> {
        let prove_start = Instant::now();
        let bls = crate::bls_baseline::BLSBenchmark::setup(batch_size);
        let prove_time = prove_start.elapsed().as_micros();
        
        let verify_start = Instant::now();
        let (success, _) = bls.verify_individual();
        let verify_time = verify_start.elapsed().as_micros();
        
        Ok(BenchmarkResult::new(
            "BLS_Individual",
            batch_size,
            exponent_bits,
            prove_time,
            verify_time,
            batch_size * 48, // BLS signature size
            success
        ))
    }
    
    #[cfg(not(feature = "bls-baseline"))]
    fn measure_bls_individual(&self, batch_size: usize, exponent_bits: usize) -> Result<BenchmarkResult, String> {
        Err("BLS baseline not enabled".to_string())
    }
    
    /// Measure BLS aggregated signature verification
    #[cfg(feature = "bls-baseline")]
    fn measure_bls_aggregated(&self, batch_size: usize, exponent_bits: usize) -> Result<BenchmarkResult, String> {
        let prove_start = Instant::now();
        let bls = crate::bls_baseline::BLSBenchmark::setup(batch_size);
        let prove_time = prove_start.elapsed().as_micros();
        
        let (success, actual_verify_time) = bls.verify_aggregated();
        
        println!("    BLS Aggregated: {} operations, {}μs verification ({}ms), success: {}", 
                 batch_size, actual_verify_time, actual_verify_time / 1000, success);
        
        Ok(BenchmarkResult::new(
            "BLS_Aggregated",
            batch_size,
            exponent_bits,
            prove_time,
            actual_verify_time,
            96, // Constant aggregated signature size
            success
        ))
    }
    
    #[cfg(not(feature = "bls-baseline"))]
    fn measure_bls_aggregated(&self, batch_size: usize, exponent_bits: usize) -> Result<BenchmarkResult, String> {
        Err("BLS baseline not enabled".to_string())
    }
    
    fn calculate_scaling_efficiency(&self, result: &BenchmarkResult) -> Option<f64> {
        // Find baseline result for efficiency comparison
        if let Some(baseline) = self.results.iter()
            .filter(|r| r.scheme == result.scheme && r.batch_size == 1_000 && r.exponent_bits == result.exponent_bits)
            .next() {
            
            let time_ratio = result.prove_time_us as f64 / baseline.prove_time_us as f64;
            let batch_ratio = result.batch_size as f64 / baseline.batch_size as f64;
            
            // Efficiency: 1.0 = perfect linear scaling, <1.0 = better than linear
            Some(time_ratio / batch_ratio)
        } else {
            None
        }
    }
    
    fn analyze_throughput_ceiling(&self) {
        println!("\n=== THROUGHPUT CEILING ANALYSIS ===");
        
        // Group results by scheme for analysis
        let mut scheme_analysis: HashMap<String, Vec<&BenchmarkResult>> = HashMap::new();
        for result in &self.results {
            scheme_analysis.entry(result.scheme.clone())
                .or_insert_with(Vec::new)
                .push(result);
        }
        
        for (scheme, results) in scheme_analysis {
            if results.is_empty() { continue; }
            
            println!("\n{} Analysis:", scheme);
            
            // Find peak throughput
            let max_throughput = results.iter()
                .max_by(|a, b| a.throughput_ops_per_sec.partial_cmp(&b.throughput_ops_per_sec).unwrap())
                .unwrap();
            
            println!("  Peak Throughput: {:.1} ops/sec at batch size {}", 
                   max_throughput.throughput_ops_per_sec, max_throughput.batch_size);
            
            // Analyze scaling characteristics
            let mut sorted_results = results.clone();
            sorted_results.sort_by_key(|r| r.batch_size);
            
            if sorted_results.len() >= 2 {
                let first = sorted_results[0];
                let last = sorted_results[sorted_results.len() - 1];
                
                let throughput_ratio = last.throughput_ops_per_sec / first.throughput_ops_per_sec;
                let batch_ratio = last.batch_size as f64 / first.batch_size as f64;
                
                println!("  Scaling: {:.2}x throughput for {:.0}x batch size", 
                       throughput_ratio, batch_ratio);
                
                if throughput_ratio > 0.8 * batch_ratio {
                    println!("  Excellent scaling (near-linear)");
                } else if throughput_ratio > 0.5 * batch_ratio {
                    println!("  Good scaling (sub-linear)");
                } else {
                    println!("  Limited scaling (degradation observed)");
                }
            }
        }
    }
    
    fn generate_o1_proof_analysis(&self) {
        println!("\n=== O(1) VERIFICATION ANALYSIS ===");
        
        // Filter zkExp results for constant-time analysis
        let zkexp_results: Vec<_> = self.results.iter()
            .filter(|r| r.scheme == "zkExp" && r.success)
            .collect();
        
        if zkexp_results.len() < 3 {
            println!("Insufficient data for O(1) analysis");
            return;
        }
        
        println!("Analyzing verification time scaling for zkExp:");
        
        // Group by exponent size for detailed analysis
        let mut exponent_groups: HashMap<usize, Vec<&BenchmarkResult>> = HashMap::new();
        for result in zkexp_results {
            exponent_groups.entry(result.exponent_bits)
                .or_insert_with(Vec::new)
                .push(result);
        }
        
        for (exp_bits, mut results) in exponent_groups {
            results.sort_by_key(|r| r.batch_size);
            
            if results.len() < 3 { continue; }
            
            println!("\n  {}-bit exponents:", exp_bits);
            
            // Calculate verification time statistics
            let verify_times: Vec<f64> = results.iter()
                .map(|r| r.verify_time_us as f64)
                .collect();
            
            let mean_verify_time = verify_times.iter().sum::<f64>() / verify_times.len() as f64;
            let variance = verify_times.iter()
                .map(|&t| (t - mean_verify_time).powi(2))
                .sum::<f64>() / verify_times.len() as f64;
            let std_dev = variance.sqrt();
            let coefficient_of_variation = std_dev / mean_verify_time;
            
            println!("    Verification time statistics:");
            println!("      Mean: {:.2}ms", mean_verify_time / 1000.0);
            println!("      Standard Deviation: {:.2}ms", std_dev / 1000.0);
            println!("      Coefficient of Variation: {:.3}", coefficient_of_variation);
            
            if coefficient_of_variation < 0.1 {
                println!("    Strong O(1) evidence (CV < 0.1)");
            } else if coefficient_of_variation < 0.2 {
                println!("    Moderate O(1) evidence (CV < 0.2)");
            } else {
                println!("    Weak O(1) evidence (CV >= 0.2)");
            }
            
            // Show testing range
            let min_batch = results.iter().map(|r| r.batch_size).min().unwrap();
            let max_batch = results.iter().map(|r| r.batch_size).max().unwrap();
            println!("    Tested range: {} to {} operations ({:.0}x scale)", 
                   min_batch, max_batch, max_batch as f64 / min_batch as f64);
        }
    }
    
    fn initialize_csv_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::create(&self.output_file)?;
        writeln!(file, "scheme,batch_size,exponent_bits,prove_time_us,verify_time_us,proof_size_bytes,success,throughput_ops_per_sec,per_operation_us,timestamp,memory_usage_mb,scaling_efficiency")?;
        Ok(())
    }
    
    fn save_result_to_csv(&self, result: &BenchmarkResult) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.output_file)?;
        writeln!(file, "{}", result.to_csv_row())?;
        Ok(())
    }
    
    fn generate_realistic_exponent_bits(&self, bits: usize) -> Vec<bool> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        let mut exponent = Vec::with_capacity(bits);
        
        // Generate cryptographically realistic random bits
        for _ in 0..bits {
            exponent.push(rng.gen_bool(0.5));
        }
        
        // Ensure most significant bit is set for full bit length
        if !exponent.is_empty() {
            exponent[bits - 1] = true;
        }
        
        exponent
    }
}

pub struct ComprehensiveBenchmark {
    pub batch_sizes: Vec<usize>,
    pub results: HashMap<String, Vec<(usize, u128, bool)>>,
    pub throughput_analysis: ThroughputCeilingAnalysis,
}

impl ComprehensiveBenchmark {
    pub fn new() -> Self {
        Self {
            batch_sizes: vec![10, 50, 100, 500, 1000],
            results: HashMap::new(),
            throughput_analysis: ThroughputCeilingAnalysis::new(),
        }
    }

    pub fn run_all_benchmarks(&mut self) {
        println!("\n=== Running Baseline Benchmarks ===");
        
        for &batch_size in &self.batch_sizes {
            println!("Running benchmarks for batch size: {}", batch_size);
            
            // Schnorr signature benchmarks
            #[cfg(feature = "schnorr-baseline")]
            {
                println!("  Testing Schnorr/Ed25519...");
                let schnorr = crate::schnorr_baseline::SchnorrBenchmark::setup(batch_size);
                
                let verify_start = std::time::Instant::now();
                let (success, _) = schnorr.verify_individual();
                let time = verify_start.elapsed().as_micros();
                
                self.results.entry("schnorr_individual".to_string())
                    .or_insert_with(Vec::new)
                    .push((batch_size, time, success));
                println!("    Individual: {}μs, success: {}", time, success);
            }
            
            // BLS signature benchmarks
            #[cfg(feature = "bls-baseline")]
            {
                println!("  Testing BLS signatures...");
                let bls = crate::bls_baseline::BLSBenchmark::setup(batch_size);
                
                let verify_start = std::time::Instant::now();
                let (success, _, _) = bls.verify_individual_detailed();
                let time = verify_start.elapsed().as_micros();
                
                self.results.entry("bls_individual".to_string())
                    .or_insert_with(Vec::new)
                    .push((batch_size, time, success));
                println!("    Individual: {}μs, success: {}", time, success);
                
                let (success, actual_agg_time) = bls.verify_aggregated();
                
                self.results.entry("bls_aggregated".to_string())
                    .or_insert_with(Vec::new)
                    .push((batch_size, actual_agg_time, success));
                println!("    Aggregated: {}μs ({}ms), success: {}", actual_agg_time, actual_agg_time / 1000, success);
            }
            
            // Groth16 SNARK benchmarks (limited to small batch sizes)
            #[cfg(feature = "groth16-baseline")]
            {
                if batch_size <= 50 {
                    println!("  Testing Groth16 SNARK...");
                    let groth16 = crate::groth16_baseline::Groth16Benchmark::setup(batch_size, 8);
                    let (success, time) = groth16.verify_individual();
                    self.results.entry("groth16_individual".to_string())
                        .or_insert_with(Vec::new)
                        .push((batch_size, time, success));
                    println!("    Verify: {}μs, success: {}", time, success);
                } else {
                    println!("  Skipping Groth16 for batch_size {} (circuit complexity)", batch_size);
                }
            }
        }
    }

    pub fn run_web3_scale_analysis(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== LARGE-SCALE THROUGHPUT ANALYSIS ===");
        self.throughput_analysis.run_ceiling_analysis()
    }
    
    pub fn print_results(&self) {
        if self.results.is_empty() {
            println!("\nNo baseline benchmarks were run.");
            println!("Enable features to run comparisons:");
            println!("  cargo run --features schnorr-baseline");
            println!("  cargo run --features bls-baseline");
            println!("  cargo run --features groth16-baseline");
            println!("  cargo run --features all-baselines");
            return;
        }

        println!("\n=== BASELINE BENCHMARK RESULTS ===");
        for (scheme, results) in &self.results {
            println!("\n{}", scheme.replace('_', " ").to_uppercase());
            println!("Batch Size | Time (μs) | Success");
            println!("-----------|-----------|--------");
            for (batch_size, time, success) in results {
                let status = if *success { "✓" } else { "✗" };
                println!("{:10} | {:9} | {}", batch_size, time, status);
            }
        }
    }

    pub fn compare_with_zkexp(&self, zkexp_results: &[(usize, u128, bool)]) {
        println!("\n=== COMPARISON: zkExp vs Baselines ===");
        
        for (batch_size, zkexp_time, zkexp_success) in zkexp_results {
            println!("\nBatch Size: {}", batch_size);
            println!("zkExp: {}μs ({})", zkexp_time, if *zkexp_success { "✓" } else { "✗" });
            
            for (scheme, results) in &self.results {
                if let Some((_, baseline_time, baseline_success)) = 
                    results.iter().find(|(bs, _, _)| bs == batch_size) {
                    
                    let speedup = if *zkexp_time > 0 {
                        *baseline_time as f64 / *zkexp_time as f64
                    } else {
                        0.0
                    };
                    
                    // Note for BLS aggregated (lacks privacy)
                    let note = if scheme == "bls_aggregated" {
                        " (NO PRIVACY)"
                    } else {
                        ""
                    };
                    
                    println!("  {}: {}μs ({:.2}x speedup) [{}]{}", 
                             scheme.replace('_', " "), 
                             baseline_time, 
                             speedup,
                             if *baseline_success { "✓" } else { "✗" },
                             note);
                }
            }
        }
        
        self.print_scaling_analysis(zkexp_results);
    }

    fn print_scaling_analysis(&self, zkexp_results: &[(usize, u128, bool)]) {
        println!("\n=== SCALING ANALYSIS ===");
        
        if zkexp_results.len() >= 2 {
            let zkexp_first = &zkexp_results[0];
            let zkexp_last = &zkexp_results[zkexp_results.len() - 1];
            
            if zkexp_first.1 > 0 {
                let zkexp_scaling = zkexp_last.1 as f64 / zkexp_first.1 as f64;
                let batch_scaling = zkexp_last.0 as f64 / zkexp_first.0 as f64;
                println!("zkExp: {:.2}x time for {:.0}x batch (efficiency: {:.2})", 
                         zkexp_scaling, batch_scaling, zkexp_scaling / batch_scaling);
            }
        }
        
        for (scheme, results) in &self.results {
            if results.len() >= 2 {
                let first = &results[0];
                let last = &results[results.len() - 1];
                
                if first.1 > 0 {
                    let time_scaling = last.1 as f64 / first.1 as f64;
                    let batch_scaling = last.0 as f64 / first.0 as f64;
                    
                    let note = if scheme == "bls_aggregated" {
                        " (constant verify time, no privacy)"
                    } else {
                        ""
                    };
                    
                    println!("{}: {:.2}x time for {:.0}x batch (efficiency: {:.2}){}", 
                             scheme.replace('_', " "), 
                             time_scaling, batch_scaling, time_scaling / batch_scaling, note);
                }
            }
        }
    }

    pub fn print_enabled_features(&self) {
        println!("\n=== ENABLED BASELINE FEATURES ===");
        
        #[cfg(feature = "schnorr-baseline")]
        println!("✓ Schnorr/Ed25519 baseline");
        #[cfg(not(feature = "schnorr-baseline"))]
        println!("✗ Schnorr/Ed25519 baseline");
        
        #[cfg(feature = "bls-baseline")]
        println!("✓ BLS signature baseline");
        #[cfg(not(feature = "bls-baseline"))]
        println!("✗ BLS signature baseline");
        
        #[cfg(feature = "groth16-baseline")]
        println!("✓ Groth16 SNARK baseline");
        #[cfg(not(feature = "groth16-baseline"))]
        println!("✗ Groth16 SNARK baseline");
    }

    /// Measure zkExp performance for comparison
    fn get_zkexp_results(&self) -> Vec<(usize, u128, bool)> {
        let mut zkexp_results = Vec::new();
        
        println!("\n=== Measuring zkExp Performance ===");
        for &batch_size in &self.batch_sizes {
            print!("  Measuring zkExp for batch size {}... ", batch_size);
            
            if let Some(result) = self.measure_zkexp_batch(batch_size) {
                println!("{}μs ({})", result.1, if result.2 { "✓" } else { "✗" });
                zkexp_results.push(result);
            } else {
                println!("FAILED");
                zkexp_results.push((batch_size, 0, false));
            }
        }
        
        zkexp_results
    }

    /// Generate realistic exponent bit patterns
    fn generate_realistic_exponent_bits(&self, bits: usize) -> Vec<bool> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        let mut exponent = Vec::with_capacity(bits);
        
        // Generate random bits with cryptographic distribution
        for _ in 0..bits {
            exponent.push(rng.gen_bool(0.5));
        }
        
        // Ensure MSB is set for full bit length
        if !exponent.is_empty() {
            exponent[bits - 1] = true;
        }
        
        // Ensure minimum Hamming weight for security
        let hamming_weight = exponent.iter().filter(|&&b| b).count();
        if hamming_weight < bits / 4 {
            for i in 0..bits {
                if exponent.iter().filter(|&&b| b).count() >= bits / 4 {
                    break;
                }
                if !exponent[i] && rng.gen_bool(0.3) {
                    exponent[i] = true;
                }
            }
        }
        
        exponent
    }

    /// Measure zkExp batch performance
    fn measure_zkexp_batch(&self, batch_size: usize) -> Option<(usize, u128, bool)> {
        // Initialize zkExp system
        let mut system = crate::zk_exp_lib::ZkExpSystem::new(
            256, false, "benchmark"
        );
        
        // Generate realistic test data
        let bases: Vec<crate::zk_exp_lib::TestField> = (0..batch_size)
            .map(|i| crate::zk_exp_lib::TestField::from((i % 97 + 2) as u64))
            .collect();
            
        let exponents: Vec<Vec<bool>> = (0..batch_size)
            .map(|_| self.generate_realistic_exponent_bits(64))
            .collect();

        // Measure proving time
        let prove_start = std::time::Instant::now();
        match system.prove_batch_exponentiations_with_metrics(&bases, &exponents, "benchmark") {
            Ok((proof, _metrics)) => {
                let prove_time = prove_start.elapsed().as_micros();
                
                // Measure verification time
                let expected_results: Vec<_> = bases.iter()
                    .zip(exponents.iter())
                    .map(|(&base, exp_bits)| system.compute_exponentiation(base, exp_bits))
                    .collect();
                
                let verify_start = std::time::Instant::now();
                let verified = system.verify_batch_exponentiations(&proof, &bases, &exponents, &expected_results);
                let verify_time = verify_start.elapsed().as_micros();
                
                // Return verification time for fair comparison with other schemes
                Some((batch_size, verify_time, verified))
            }
            Err(_) => None
        }
    }
}

/// Main function for comprehensive benchmark analysis
pub fn run_comprehensive_comparison_with_ceiling_analysis() {
    let mut benchmark = ComprehensiveBenchmark::new();
    
    println!("=== COMPREHENSIVE zkExp BENCHMARK SUITE ===");
    println!("Note: All timing measurements are actual, not simulated");
    
    // Run standard benchmarks
    benchmark.print_enabled_features();
    benchmark.run_all_benchmarks();
    benchmark.print_results();
    
    // Get zkExp results for comparison
    let zkexp_results = benchmark.get_zkexp_results();
    benchmark.compare_with_zkexp(&zkexp_results);
    
    // Run large-scale throughput analysis
    match benchmark.run_web3_scale_analysis() {
        Ok(_) => {
            println!("\nLarge-scale analysis completed successfully!");
            println!("CSV results saved for plotting and analysis");
        }
        Err(e) => {
            println!("Large-scale analysis failed: {}", e);
        }
    }
    
    println!("\n=== ANALYSIS COMPLETE ===");
    println!("Use the generated CSV file for:");
    println!("  • Plotting throughput vs batch size");
    println!("  • O(1) verification time analysis");
    println!("  • Comparison with existing schemes");
    println!("  • Scaling efficiency visualization");
    println!("Results: {}", benchmark.throughput_analysis.output_file);
    
    // Performance expectations summary
    println!("\n=== EXPECTED PERFORMANCE CHARACTERISTICS ===");
    println!("Based on pairing performance (~1.5ms per pairing):");
    println!("  zkExp verification:    ~3-10ms (constant)");
    println!("  BLS Individual:        ~90-3000ms (linear scaling)");
    println!("  BLS Aggregated:        ~1500ms for 1000 sigs (1001 pairings)");
    println!("  Schnorr:              ~100-120ms (linear scaling)");
    println!("  Naive Exponentiation: ~128-1024ms (depends on exp size)");
    println!("\nzkExp should demonstrate significant improvement over baseline schemes!");
}

/// Backward compatibility alias
pub fn run_comprehensive_comparison() {
    run_comprehensive_comparison_with_ceiling_analysis();
}
