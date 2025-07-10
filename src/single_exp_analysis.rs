/// Single Exponentiation Analysis Module
///
/// This module provides performance analysis for single exponentiation operations
/// across different bit lengths, comparing zkExp protocol performance with
/// traditional exponentiation methods.
///
/// Features:
/// - Bit length scaling analysis
/// - Performance comparison with traditional methods
/// - Memory usage estimation
/// - Efficiency metrics calculation

use crate::zk_exp_lib::*;
use std::fs;
use chrono::Utc;
use std::time::Instant;

/// Analyzer for single exponentiation performance across bit lengths
pub struct SingleExponentiationAnalyzer {
    system: ZkExpSystem,
    sliding_window_size: usize,
    results: Vec<SingleExpResult>,
    traditional_results: Vec<TraditionalExpResult>,
}

/// Result structure for zkExp single exponentiation tests
#[derive(Debug, Clone)]
pub struct SingleExpResult {
    pub bit_length: usize,
    pub prove_time_us: u64,
    pub verify_time_us: u64,
    pub proof_size_bytes: usize,
    pub memory_usage_bytes: usize,
    pub verification_success: bool,
    pub efficiency_score: f64,
}

/// Result structure for traditional exponentiation tests
#[derive(Debug, Clone)]
pub struct TraditionalExpResult {
    pub bit_length: usize,
    pub compute_time_us: u64,
    pub verify_time_us: u64,
    pub memory_usage_bytes: usize,
    pub verification_success: bool,
}

impl SingleExponentiationAnalyzer {
    /// Create new analyzer with specified sliding window size
    pub fn new(sliding_window_size: usize) -> Self {
        let system = ZkExpSystem::new(4096, true, "single_exp_analyzer");
        
        Self {
            system,
            sliding_window_size,
            results: Vec::new(),
            traditional_results: Vec::new(),
        }
    }
    
    /// Run comprehensive bit length analysis
    pub fn run_comprehensive_analysis(&mut self) -> Result<(), String> {
        println!("=== Single Exponentiation Analysis ===");
        println!("Sliding window size: {}", self.sliding_window_size);
        
        // Define test ranges
        let small_bits = vec![4, 8, 16, 32, 64];
        let medium_bits = vec![128, 256, 512];
        let large_bits = vec![1024, 2048, 4096];
        
        // Run tests in phases
        println!("\nPhase 1: Small exponents (4-64 bits)");
        self.run_bit_range_tests(&small_bits)?;
        
        println!("\nPhase 2: Medium exponents (128-512 bits)");
        self.run_bit_range_tests(&medium_bits)?;
        
        println!("\nPhase 3: Large exponents (1024-4096 bits)");
        self.run_bit_range_tests(&large_bits)?;
        
        // Generate analysis and save results
        self.generate_analysis_report()?;
        self.save_results_to_csv()?;
        
        Ok(())
    }
    
    /// Run tests for a specific range of bit lengths
    fn run_bit_range_tests(&mut self, bit_lengths: &[usize]) -> Result<(), String> {
        for &bit_length in bit_lengths {
            println!("Testing {}-bit exponents...", bit_length);
            
            // Generate test data
            let exponent_bits = self.generate_test_exponent(bit_length);
            let base = TestField::from(3u64);
            let test_name = format!("Single_{}bit", bit_length);
            
            // Measure traditional exponentiation
            let traditional_result = self.measure_traditional_exponentiation(base, &exponent_bits, bit_length);
            
            // Measure zkExp performance
            match self.system.prove_single_exponentiation_with_metrics(
                base, &exponent_bits, &test_name
            ) {
                Ok((proof, metric)) => {
                    // Verify the result
                    let expected = self.system.compute_exponentiation(base, &exponent_bits);
                    let verified = self.system.verify_sliding_window_batch(
                        &proof, 
                        &[base], 
                        &[exponent_bits], 
                        &[expected]
                    );
                    
                    // Calculate efficiency score
                    let efficiency = if metric.prove_time_us > 0 {
                        (bit_length as f64) / (metric.prove_time_us as f64 / 1000.0)
                    } else {
                        0.0
                    };
                    
                    // Store zkExp result
                    let zkexp_result = SingleExpResult {
                        bit_length,
                        prove_time_us: metric.prove_time_us,
                        verify_time_us: metric.verify_time_us,
                        proof_size_bytes: metric.proof_size_bytes,
                        memory_usage_bytes: self.estimate_memory_usage(bit_length),
                        verification_success: verified,
                        efficiency_score: efficiency,
                    };
                    
                    self.results.push(zkexp_result.clone());
                    self.traditional_results.push(traditional_result.clone());
                    
                    // Print comparison
                    self.print_comparison_results(&traditional_result, &zkexp_result, bit_length);
                }
                Err(e) => {
                    println!("  Failed: {}", e);
                    
                    // Store failure result
                    let failed_result = SingleExpResult {
                        bit_length,
                        prove_time_us: 0,
                        verify_time_us: 0,
                        proof_size_bytes: 0,
                        memory_usage_bytes: 0,
                        verification_success: false,
                        efficiency_score: 0.0,
                    };
                    self.results.push(failed_result);
                }
            }
        }
        
        Ok(())
    }
    
    /// Measure traditional exponentiation performance
    fn measure_traditional_exponentiation(&self, base: TestField, exponent_bits: &[bool], bit_length: usize) -> TraditionalExpResult {
        // Measure computation time
        let start = Instant::now();
        let result = self.traditional_exponentiation_full_bits(base, exponent_bits);
        let compute_time = start.elapsed().as_micros().max(1) as u64;
        
        // Traditional verification is recomputation
        let verify_start = Instant::now();
        let verify_result = self.traditional_exponentiation_full_bits(base, exponent_bits);
        let verify_time = verify_start.elapsed().as_micros() as u64;
        
        let verification_success = result == verify_result;
        
        TraditionalExpResult {
            bit_length,
            compute_time_us: compute_time,
            verify_time_us: verify_time,
            memory_usage_bytes: 64, // Minimal memory usage
            verification_success,
        }
    }
    
    /// Traditional exponentiation using repeated squaring
    fn traditional_exponentiation_full_bits(&self, base: TestField, exponent_bits: &[bool]) -> TestField {
        use ark_ff::{Field, One};
        
        let mut result = TestField::one();
        let mut base_power = base;
        
        for &bit in exponent_bits {
            if bit {
                result *= base_power;
            }
            base_power = base_power.square();
        }
        
        result
    }
    
    /// Print comparison between traditional and zkExp results
    fn print_comparison_results(&self, traditional: &TraditionalExpResult, zkexp: &SingleExpResult, bit_length: usize) {
        println!("  {}-bit results:", bit_length);
        println!("    Traditional: {}μs compute, {}μs verify, {}B memory", 
                 traditional.compute_time_us, traditional.verify_time_us, traditional.memory_usage_bytes);
        println!("    zkExp:       {}μs prove,   {}μs verify, {}B proof + {}MB memory", 
                 zkexp.prove_time_us, zkexp.verify_time_us, zkexp.proof_size_bytes, zkexp.memory_usage_bytes / (1024*1024));
        
        // Calculate metrics
        let prove_overhead = if traditional.compute_time_us > 0 {
            zkexp.prove_time_us as f64 / traditional.compute_time_us as f64
        } else { 0.0 };
        
        let verify_speedup = if zkexp.verify_time_us > 0 {
            traditional.verify_time_us as f64 / zkexp.verify_time_us as f64
        } else { 0.0 };
        
        println!("    Overhead: {:.1}x prove time, {:.1}x verify speedup", prove_overhead, verify_speedup);
    }
    
    /// Generate deterministic test exponent
    fn generate_test_exponent(&self, bit_length: usize) -> Vec<bool> {
        if bit_length == 0 {
            return vec![false];
        }
        
        let mut bits = vec![false; bit_length];
        
        // Set MSB to ensure exact bit length
        bits[bit_length - 1] = true;
        
        // Create deterministic pattern
        for i in 0..bit_length {
            if (i * 17 + bit_length * 3) % 7 < 3 {
                bits[i] = true;
            }
        }
        
        bits
    }
    
    /// Estimate memory usage based on bit length
    fn estimate_memory_usage(&self, bit_length: usize) -> usize {
        let base_memory = 1024 * 1024; // 1MB base
        let scaling_memory = ((bit_length as f64).sqrt() * 1024.0) as usize;
        base_memory + scaling_memory
    }
    
    /// Generate comprehensive analysis report
    fn generate_analysis_report(&self) -> Result<(), String> {
        println!("\n=== Analysis Report ===");
        
        if self.results.is_empty() {
            return Err("No results to analyze".to_string());
        }
        
        self.analyze_performance_scaling();
        self.analyze_efficiency_trends();
        self.analyze_memory_scaling();
        
        Ok(())
    }
    
    /// Analyze performance scaling with bit length
    fn analyze_performance_scaling(&self) {
        println!("\nPerformance Scaling:");
        
        let successful_results: Vec<_> = self.results.iter()
            .filter(|r| r.verification_success)
            .collect();
        
        if successful_results.len() < 2 {
            println!("Insufficient data for scaling analysis");
            return;
        }
        
        // Simple linear regression for prove time vs bit length
        let n = successful_results.len() as f64;
        let sum_x: f64 = successful_results.iter().map(|r| r.bit_length as f64).sum();
        let sum_y: f64 = successful_results.iter().map(|r| r.prove_time_us as f64).sum();
        let sum_xy: f64 = successful_results.iter()
            .map(|r| (r.bit_length as f64) * (r.prove_time_us as f64))
            .sum();
        let sum_x2: f64 = successful_results.iter()
            .map(|r| (r.bit_length as f64).powi(2))
            .sum();
        
        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x.powi(2));
        let intercept = (sum_y - slope * sum_x) / n;
        
        println!("  Prove time scaling: {:.2}μs per bit + {:.0}μs base", slope, intercept);
        
        // Verification time analysis
        let verify_times: Vec<_> = successful_results.iter().map(|r| r.verify_time_us).collect();
        let avg_verify = verify_times.iter().sum::<u64>() as f64 / verify_times.len() as f64;
        
        println!("  Average verify time: {:.0}μs (should be constant)", avg_verify);
    }
    
    /// Analyze efficiency trends
    fn analyze_efficiency_trends(&self) {
        println!("\nEfficiency Analysis:");
        
        let successful_results: Vec<_> = self.results.iter()
            .filter(|r| r.verification_success && r.efficiency_score > 0.0)
            .collect();
        
        if successful_results.is_empty() {
            println!("No successful results for efficiency analysis");
            return;
        }
        
        // Find best and worst efficiency
        let best = successful_results.iter().max_by(|a, b| 
            a.efficiency_score.partial_cmp(&b.efficiency_score).unwrap()).unwrap();
        let worst = successful_results.iter().min_by(|a, b| 
            a.efficiency_score.partial_cmp(&b.efficiency_score).unwrap()).unwrap();
        
        println!("  Best efficiency: {:.1} bits/ms ({}-bit)", 
                 best.efficiency_score, best.bit_length);
        println!("  Worst efficiency: {:.1} bits/ms ({}-bit)", 
                 worst.efficiency_score, worst.bit_length);
    }
    
    /// Analyze memory scaling
    fn analyze_memory_scaling(&self) {
        println!("\nMemory Scaling:");
        
        for result in &self.results {
            if result.verification_success {
                let memory_mb = result.memory_usage_bytes as f64 / (1024.0 * 1024.0);
                println!("  {}-bit: {:.1}MB estimated", result.bit_length, memory_mb);
            }
        }
    }
    
    /// Save results to CSV file
    fn save_results_to_csv(&self) -> Result<(), String> {
        let filename = format!("single_exp_analysis_{}.csv", 
                              Utc::now().format("%Y%m%d_%H%M%S"));
        
        let mut content = String::from(
            "bit_length,zkexp_prove_time_us,zkexp_verify_time_us,zkexp_proof_size_bytes,\
             zkexp_memory_usage_bytes,zkexp_verification_success,zkexp_efficiency_score,\
             traditional_compute_time_us,traditional_verify_time_us,traditional_memory_usage_bytes,\
             zk_overhead_factor\n"
        );
        
        for result in &self.results {
            // Find corresponding traditional result
            let traditional = self.traditional_results.iter()
                .find(|t| t.bit_length == result.bit_length);
                
            if let Some(trad) = traditional {
                let zk_overhead = if trad.compute_time_us > 0 {
                    result.prove_time_us as f64 / trad.compute_time_us as f64
                } else {
                    0.0
                };
                
                content.push_str(&format!(
                    "{},{},{},{},{},{},{:.2},{},{},{},{:.2}\n",
                    result.bit_length,
                    result.prove_time_us,
                    result.verify_time_us,
                    result.proof_size_bytes,
                    result.memory_usage_bytes,
                    result.verification_success,
                    result.efficiency_score,
                    trad.compute_time_us,
                    trad.verify_time_us,
                    trad.memory_usage_bytes,
                    zk_overhead
                ));
            } else {
                content.push_str(&format!(
                    "{},{},{},{},{},{},{:.2},0,0,0,0.0\n",
                    result.bit_length,
                    result.prove_time_us,
                    result.verify_time_us,
                    result.proof_size_bytes,
                    result.memory_usage_bytes,
                    result.verification_success,
                    result.efficiency_score
                ));
            }
        }
        
        std::fs::write(&filename, content)
            .map_err(|e| format!("Failed to save CSV: {}", e))?;
        
        println!("Results saved to: {}", filename);
        Ok(())
    }
    
    /// Get summary statistics
    pub fn get_summary(&self) -> String {
        let successful = self.results.iter().filter(|r| r.verification_success).count();
        let total = self.results.len();
        
        if successful == 0 {
            return "No successful tests completed".to_string();
        }
        
        let successful_results: Vec<_> = self.results.iter()
            .filter(|r| r.verification_success)
            .collect();
        
        let min_bits = successful_results.iter().map(|r| r.bit_length).min().unwrap();
        let max_bits = successful_results.iter().map(|r| r.bit_length).max().unwrap();
        let avg_prove_time = successful_results.iter().map(|r| r.prove_time_us).sum::<u64>() / successful.max(1) as u64;
        
        format!(
            "Tested {}/{} bit lengths successfully. Range: {}-{} bits. Avg prove time: {}μs",
            successful, total, min_bits, max_bits, avg_prove_time
        )
    }
}

/// Main entry point for single exponentiation analysis
pub fn run_single_exponentiation_analysis() {
    println!("Starting single exponentiation analysis...");
    
    let mut analyzer = SingleExponentiationAnalyzer::new(32);
    
    match analyzer.run_comprehensive_analysis() {
        Ok(()) => {
            println!("\nAnalysis completed successfully!");
            println!("{}", analyzer.get_summary());
        }
        Err(e) => {
            println!("Analysis failed: {}", e);
        }
    }
}
