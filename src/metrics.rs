/// Performance Metrics Collection for Zero-Knowledge Proof Systems
/// 
/// This module provides standardized measurement and analysis capabilities
/// for evaluating zero-knowledge proof protocol performance. It supports
/// timing analysis, memory profiling, and comparative studies between
/// different proof systems.
///
/// Core functionality includes:
/// - Comprehensive performance metrics collection
/// - Statistical analysis and confidence intervals
/// - CSV and JSON export capabilities
/// - Protocol comparison and improvement factor analysis

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use chrono::{DateTime, Utc};

/// Core metrics structure for zero-knowledge proof performance evaluation
#[derive(Clone, Debug)]
pub struct ZKProofMetrics {
    pub protocol_name: String,
    pub test_case: String,
    pub timestamp: DateTime<Utc>,
    
    // Performance timing (microseconds)
    pub setup_time_us: u64,
    pub prove_time_us: u64,
    pub verify_time_us: u64,
    
    // Size measurements (bytes)
    pub proof_size_bytes: usize,
    pub memory_peak_bytes: usize,
    
    // Verification results
    pub verification_success: bool,
    pub verification_constant_time: bool,
    pub expected_result: Option<String>,
    
    // Configuration parameters
    pub batch_size: Option<usize>,
    pub exponent_bits: Option<usize>,
    pub thread_count: Option<usize>,
    pub security_level: Option<usize>,
    pub window_size: Option<usize>,
    
    // Derived performance metrics
    pub per_proof_time_us: Option<u64>,
    pub throughput_ops_per_sec: Option<f64>,
    pub memory_efficiency_bytes_per_op: Option<usize>,
    
    // Comparative analysis
    pub improvement_factor_prove_time: Option<f64>,
    pub improvement_factor_verify_time: Option<f64>,
    pub improvement_factor_proof_size: Option<f64>,
    pub improvement_factor_memory: Option<f64>,
}

impl ZKProofMetrics {
    /// Create new metrics instance for a specific test
    pub fn new(protocol_name: &str, test_case: &str) -> Self {
        Self {
            protocol_name: protocol_name.to_string(),
            test_case: test_case.to_string(),
            timestamp: Utc::now(),
            setup_time_us: 0,
            prove_time_us: 0,
            verify_time_us: 0,
            proof_size_bytes: 0,
            memory_peak_bytes: 0,
            verification_success: false,
            verification_constant_time: false,
            expected_result: None,
            batch_size: None,
            exponent_bits: None,
            thread_count: None,
            security_level: None,
            window_size: None,
            per_proof_time_us: None,
            throughput_ops_per_sec: None,
            memory_efficiency_bytes_per_op: None,
            improvement_factor_prove_time: None,
            improvement_factor_verify_time: None,
            improvement_factor_proof_size: None,
            improvement_factor_memory: None,
        }
    }

    /// Set sliding window configuration
    pub fn set_window_info(&mut self, window_size: usize, memory_reduction: Option<f64>) {
        self.window_size = Some(window_size);
        if let Some(reduction) = memory_reduction {
            self.improvement_factor_memory = Some(reduction);
        }
    }
    
    /// Calculate memory efficiency metrics
    pub fn calculate_memory_efficiency(&mut self) {
        if let (Some(batch_size), Some(window_size)) = (self.batch_size, self.window_size) {
            let theoretical_reduction = batch_size as f64 / window_size as f64;
            self.improvement_factor_memory = Some(theoretical_reduction);
            
            if self.memory_peak_bytes > 0 && batch_size > 0 {
                self.memory_efficiency_bytes_per_op = Some(self.memory_peak_bytes / batch_size);
            }
        }
    }

    /// Set timing measurements
    pub fn set_timing(&mut self, setup_us: u64, prove_us: u64, verify_us: u64) {
        self.setup_time_us = setup_us;
        self.prove_time_us = prove_us;
        self.verify_time_us = verify_us;
    }
    
    /// Set size measurements
    pub fn set_sizes(&mut self, proof_bytes: usize, memory_bytes: usize) {
        self.proof_size_bytes = proof_bytes;
        self.memory_peak_bytes = memory_bytes;
        
        if let Some(batch_size) = self.batch_size {
            if batch_size > 0 {
                self.memory_efficiency_bytes_per_op = Some(memory_bytes / batch_size);
            }
        } else {
            self.memory_efficiency_bytes_per_op = Some(memory_bytes);
        }
    }
    
    /// Set verification results
    pub fn set_verification(&mut self, success: bool, expected: Option<String>) {
        self.verification_success = success;
        self.expected_result = expected;
    }
    
    /// Set baseline comparison factors
    pub fn set_comparison_baseline(&mut self, baseline: &ZKProofMetrics) {
        if baseline.prove_time_us > 0 {
            self.improvement_factor_prove_time = Some(baseline.prove_time_us as f64 / self.prove_time_us as f64);
        }
        
        if baseline.verify_time_us > 0 {
            self.improvement_factor_verify_time = Some(baseline.verify_time_us as f64 / self.verify_time_us as f64);
        }
        
        if baseline.proof_size_bytes > 0 {
            self.improvement_factor_proof_size = Some(baseline.proof_size_bytes as f64 / self.proof_size_bytes as f64);
        }
        
        if baseline.memory_peak_bytes > 0 {
            self.improvement_factor_memory = Some(baseline.memory_peak_bytes as f64 / self.memory_peak_bytes as f64);
        }
    }
    
    /// Calculate derived performance metrics
    pub fn calculate_derived_metrics(&mut self) {
        if let Some(batch_size) = self.batch_size {
            if batch_size > 0 {
                self.per_proof_time_us = Some(self.prove_time_us / batch_size as u64);
                
                if self.prove_time_us > 0 {
                    let prove_time_seconds = self.prove_time_us as f64 / 1_000_000.0;
                    self.throughput_ops_per_sec = Some(batch_size as f64 / prove_time_seconds);
                }
            }
        }
    }
    
    /// Export metrics as CSV row
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.protocol_name,
            self.test_case,
            self.timestamp.format("%Y-%m-%d %H:%M:%S"),
            self.setup_time_us,
            self.prove_time_us,
            self.verify_time_us,
            self.proof_size_bytes,
            self.memory_peak_bytes,
            self.verification_success,
            self.verification_constant_time,
            self.batch_size.map_or("".to_string(), |v| v.to_string()),
            self.exponent_bits.map_or("".to_string(), |v| v.to_string()),
            self.thread_count.map_or("".to_string(), |v| v.to_string()),
            self.security_level.map_or("".to_string(), |v| v.to_string()),
            self.window_size.map_or("".to_string(), |v| v.to_string()),
            self.per_proof_time_us.map_or("".to_string(), |v| v.to_string()),
            self.throughput_ops_per_sec.map_or("".to_string(), |v| format!("{:.2}", v)),
            self.memory_efficiency_bytes_per_op.map_or("".to_string(), |v| v.to_string()),
            self.improvement_factor_prove_time.map_or("".to_string(), |v| format!("{:.2}", v)),
            self.improvement_factor_verify_time.map_or("".to_string(), |v| format!("{:.2}", v)),
            self.improvement_factor_proof_size.map_or("".to_string(), |v| format!("{:.2}", v)),
            self.improvement_factor_memory.map_or("".to_string(), |v| format!("{:.2}", v))
        )
    }
    
    /// Get CSV header for export
    pub fn csv_header() -> String {
        "protocol_name,test_case,timestamp,setup_time_us,prove_time_us,verify_time_us,proof_size_bytes,memory_peak_bytes,verification_success,verification_constant_time,batch_size,exponent_bits,thread_count,security_level,window_size,per_proof_time_us,throughput_ops_per_sec,memory_efficiency_bytes_per_op,improvement_factor_prove_time,improvement_factor_verify_time,improvement_factor_proof_size,improvement_factor_memory".to_string()
    }
}

/// Metrics collector for aggregating and analyzing benchmark results
pub struct MetricsCollector {
    pub session_name: String,
    pub metrics_history: Vec<ZKProofMetrics>,
    pub protocol_summaries: HashMap<String, ProtocolSummary>,
    pub start_time: DateTime<Utc>,
}

/// Summary statistics for a protocol across multiple test cases
#[derive(Clone, Debug)]
pub struct ProtocolSummary {
    pub protocol_name: String,
    pub test_count: usize,
    pub avg_prove_time_us: f64,
    pub avg_verify_time_us: f64,
    pub avg_proof_size_bytes: f64,
    pub avg_memory_bytes: f64,
    pub success_rate: f64,
    pub total_batch_size: usize,
    pub avg_throughput_ops_per_sec: f64,
}

impl MetricsCollector {
    /// Create new metrics collector for a benchmark session
    pub fn new(session_name: &str) -> Self {
        Self {
            session_name: session_name.to_string(),
            metrics_history: Vec::new(),
            protocol_summaries: HashMap::new(),
            start_time: Utc::now(),
        }
    }
    
    /// Add new metric to collection
    pub fn add_metric(&mut self, mut metric: ZKProofMetrics) {
        metric.calculate_derived_metrics();
        self.update_protocol_summary(&metric);
        self.metrics_history.push(metric);
    }
    
    /// Update running statistics for a protocol
    fn update_protocol_summary(&mut self, metric: &ZKProofMetrics) {
        let protocol_name = &metric.protocol_name;
        
        let summary = self.protocol_summaries.entry(protocol_name.clone())
            .or_insert_with(|| ProtocolSummary {
                protocol_name: protocol_name.clone(),
                test_count: 0,
                avg_prove_time_us: 0.0,
                avg_verify_time_us: 0.0,
                avg_proof_size_bytes: 0.0,
                avg_memory_bytes: 0.0,
                success_rate: 0.0,
                total_batch_size: 0,
                avg_throughput_ops_per_sec: 0.0,
            });
        
        let n = summary.test_count as f64;
        let new_n = n + 1.0;
        
        summary.avg_prove_time_us = (summary.avg_prove_time_us * n + metric.prove_time_us as f64) / new_n;
        summary.avg_verify_time_us = (summary.avg_verify_time_us * n + metric.verify_time_us as f64) / new_n;
        summary.avg_proof_size_bytes = (summary.avg_proof_size_bytes * n + metric.proof_size_bytes as f64) / new_n;
        summary.avg_memory_bytes = (summary.avg_memory_bytes * n + metric.memory_peak_bytes as f64) / new_n;
        
        let current_successes = summary.success_rate * n;
        let new_successes = current_successes + if metric.verification_success { 1.0 } else { 0.0 };
        summary.success_rate = new_successes / new_n;
        
        if let Some(batch_size) = metric.batch_size {
            summary.total_batch_size += batch_size;
        }
        
        if let Some(throughput) = metric.throughput_ops_per_sec {
            summary.avg_throughput_ops_per_sec = (summary.avg_throughput_ops_per_sec * n + throughput) / new_n;
        }
        
        summary.test_count += 1;
    }
    
    /// Print comprehensive benchmark summary
    pub fn print_summary(&self) {
        println!("\n=== Benchmark Session Summary: {} ===", self.session_name);
        println!("Duration: {:.1} minutes", 
                Utc::now().signed_duration_since(self.start_time).num_seconds() as f64 / 60.0);
        println!("Total tests: {}", self.metrics_history.len());
        println!("Protocols tested: {}", self.protocol_summaries.len());
        
        println!("\n--- Protocol Performance Comparison ---");
        println!("| Protocol           | Tests | Prove    | Verify   | Size    | Success | Throughput |");
        println!("|-------------------|-------|----------|----------|---------|---------|------------|");
        
        let mut summaries: Vec<_> = self.protocol_summaries.values().collect();
        summaries.sort_by(|a, b| a.avg_prove_time_us.partial_cmp(&b.avg_prove_time_us).unwrap());
        
        for summary in &summaries {
            println!("| {:17} | {:5} | {:6.1}μs | {:6.1}μs | {:5.0}B | {:5.1}% | {:8.0}/s |",
                summary.protocol_name,
                summary.test_count,
                summary.avg_prove_time_us,
                summary.avg_verify_time_us,
                summary.avg_proof_size_bytes,
                summary.success_rate * 100.0,
                summary.avg_throughput_ops_per_sec
            );
        }
        
        if !self.protocol_summaries.is_empty() {
            let fastest_prove = summaries.iter().min_by(|a, b| 
                a.avg_prove_time_us.partial_cmp(&b.avg_prove_time_us).unwrap()).unwrap();
            let fastest_verify = summaries.iter().min_by(|a, b| 
                a.avg_verify_time_us.partial_cmp(&b.avg_verify_time_us).unwrap()).unwrap();
            let smallest_proof = summaries.iter().min_by(|a, b| 
                a.avg_proof_size_bytes.partial_cmp(&b.avg_proof_size_bytes).unwrap()).unwrap();
            let highest_throughput = summaries.iter().max_by(|a, b| 
                a.avg_throughput_ops_per_sec.partial_cmp(&b.avg_throughput_ops_per_sec).unwrap()).unwrap();
                
            println!("\n--- Performance Leaders ---");
            println!("Fastest proving: {} ({:.1}μs average)", 
                    fastest_prove.protocol_name, fastest_prove.avg_prove_time_us);
            println!("Fastest verification: {} ({:.1}μs average)", 
                    fastest_verify.protocol_name, fastest_verify.avg_verify_time_us);
            println!("Smallest proofs: {} ({:.0} bytes average)", 
                    smallest_proof.protocol_name, smallest_proof.avg_proof_size_bytes);
            println!("Highest throughput: {} ({:.0} ops/sec)", 
                    highest_throughput.protocol_name, highest_throughput.avg_throughput_ops_per_sec);
        }
    }
    
    /// Export metrics to CSV file
    pub fn export_to_csv(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::create(filename)?;
        
        writeln!(file, "{}", ZKProofMetrics::csv_header())?;
        
        for metric in &self.metrics_history {
            writeln!(file, "{}", metric.to_csv_row())?;
        }
        
        println!("Exported {} metrics to {}", self.metrics_history.len(), filename);
        Ok(())
    }
    
    /// Generate comparative analysis between protocols
    pub fn generate_comparison_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str("=== Protocol Comparison Analysis ===\n");
        
        if self.protocol_summaries.len() < 2 {
            report.push_str("Need at least 2 protocols for comparison analysis\n");
            return report;
        }
        
        let summaries: Vec<_> = self.protocol_summaries.values().collect();
        
        let zkexp_summary = summaries.iter().find(|s| s.protocol_name.contains("zkExp"));
        
        if let Some(zkexp) = zkexp_summary {
            report.push_str("\n--- zkExp Performance Advantages ---\n");
            report.push_str(&format!("zkExp baseline: {:.1}μs prove, {:.1}μs verify, {:.0}B proof\n",
                zkexp.avg_prove_time_us, zkexp.avg_verify_time_us, zkexp.avg_proof_size_bytes));
            
            for summary in &summaries {
                if summary.protocol_name == zkexp.protocol_name {
                    continue;
                }
                
                let prove_speedup = summary.avg_prove_time_us / zkexp.avg_prove_time_us;
                let verify_speedup = summary.avg_verify_time_us / zkexp.avg_verify_time_us;
                let size_ratio = summary.avg_proof_size_bytes / zkexp.avg_proof_size_bytes;
                
                report.push_str(&format!("\nvs {}:\n", summary.protocol_name));
                report.push_str(&format!("  Proving: {:.1}x improvement\n", prove_speedup));
                report.push_str(&format!("  Verification: {:.1}x improvement\n", verify_speedup));
                report.push_str(&format!("  Proof size: {:.1}x reduction\n", size_ratio));
            }
        }
        
        report.push_str("\n--- Scalability Analysis ---\n");
        
        let mut batch_metrics: HashMap<usize, Vec<&ZKProofMetrics>> = HashMap::new();
        for metric in &self.metrics_history {
            if let Some(batch_size) = metric.batch_size {
                batch_metrics.entry(batch_size).or_insert_with(Vec::new).push(metric);
            }
        }
        
        let mut batch_sizes: Vec<_> = batch_metrics.keys().cloned().collect();
        batch_sizes.sort();
        
        for protocol_name in self.protocol_summaries.keys() {
            if batch_sizes.len() > 1 {
                report.push_str(&format!("\n{} scaling:\n", protocol_name));
                
                for &batch_size in &batch_sizes {
                    if let Some(metrics) = batch_metrics.get(&batch_size) {
                        let protocol_metrics: Vec<_> = metrics.iter()
                            .filter(|m| m.protocol_name == *protocol_name)
                            .collect();
                        
                        if !protocol_metrics.is_empty() {
                            let avg_per_proof = protocol_metrics.iter()
                                .filter_map(|m| m.per_proof_time_us)
                                .sum::<u64>() as f64 / protocol_metrics.len() as f64;
                            
                            report.push_str(&format!("  Batch {}: {:.1}μs per operation\n",
                                batch_size, avg_per_proof));
                        }
                    }
                }
            }
        }
        
        report
    }
    
    /// Save all data and generate final reports
    pub fn finalize_session(&self) {
        let timestamp = self.start_time.format("%Y%m%d_%H%M%S");
        let csv_filename = format!("{}_{}_metrics.csv", self.session_name, timestamp);
        let comparison_filename = format!("{}_{}_comparison.txt", self.session_name, timestamp);
        
        if let Err(e) = self.export_to_csv(&csv_filename) {
            println!("Warning: Failed to export CSV: {}", e);
        }
        
        let comparison_report = self.generate_comparison_report();
        if let Ok(mut file) = File::create(&comparison_filename) {
            if let Err(e) = file.write_all(comparison_report.as_bytes()) {
                println!("Warning: Failed to write comparison report: {}", e);
            }
        }
        
        self.print_summary();
        
        println!("\n=== Session Results ===");
        println!("Data: {}", csv_filename);
        println!("Analysis: {}", comparison_filename);
    }
}

/// Statistical analysis for benchmark results
pub struct BenchmarkAggregator {
    pub results: Vec<ZKProofMetrics>,
    pub confidence_level: f64,
}

impl BenchmarkAggregator {
    /// Create new statistical aggregator
    pub fn new(confidence_level: f64) -> Self {
        Self {
            results: Vec::new(),
            confidence_level,
        }
    }
    
    /// Add result for statistical analysis
    pub fn add_result(&mut self, result: ZKProofMetrics) {
        self.results.push(result);
    }
    
    /// Calculate confidence intervals for timing measurements
    pub fn calculate_confidence_intervals(&self, protocol_name: &str) -> Option<(f64, f64, f64)> {
        let protocol_results: Vec<_> = self.results.iter()
            .filter(|r| r.protocol_name == protocol_name)
            .collect();
        
        if protocol_results.len() < 3 {
            return None;
        }
        
        let prove_times: Vec<f64> = protocol_results.iter()
            .map(|r| r.prove_time_us as f64)
            .collect();
        
        let mean = prove_times.iter().sum::<f64>() / prove_times.len() as f64;
        let variance = prove_times.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / (prove_times.len() - 1) as f64;
        let std_dev = variance.sqrt();
        
        let margin = 1.96 * std_dev / (prove_times.len() as f64).sqrt();
        
        Some((mean - margin, mean, mean + margin))
    }
    
    /// Perform statistical significance test between two protocols
    pub fn welch_t_test(&self, protocol_a: &str, protocol_b: &str) -> Option<f64> {
        let results_a: Vec<_> = self.results.iter()
            .filter(|r| r.protocol_name == protocol_a)
            .map(|r| r.prove_time_us as f64)
            .collect();
        
        let results_b: Vec<_> = self.results.iter()
            .filter(|r| r.protocol_name == protocol_b)
            .map(|r| r.prove_time_us as f64)
            .collect();
        
        if results_a.len() < 2 || results_b.len() < 2 {
            return None;
        }
        
        let mean_a = results_a.iter().sum::<f64>() / results_a.len() as f64;
        let mean_b = results_b.iter().sum::<f64>() / results_b.len() as f64;
        
        let var_a = results_a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (results_a.len() - 1) as f64;
        let var_b = results_b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (results_b.len() - 1) as f64;
        
        let se_a = var_a / results_a.len() as f64;
        let se_b = var_b / results_b.len() as f64;
        
        let t_stat = (mean_a - mean_b) / (se_a + se_b).sqrt();
        
        Some(t_stat.abs())
    }
}
