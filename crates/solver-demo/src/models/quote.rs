use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use solver_types::api::{GetQuoteRequest, GetQuoteResponse};
use std::path::PathBuf;

/// Saved quote request with metadata for local storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQuoteRequest {
    /// The original quote request
    pub request: GetQuoteRequest,
    /// When this request was saved
    pub saved_at: DateTime<Utc>,
    /// File path where this was saved
    pub file_path: PathBuf,
    /// Optional description/notes
    pub description: Option<String>,
}

/// Saved quote response with metadata for local storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQuoteResponse {
    /// The original quote response from API
    pub response: GetQuoteResponse,
    /// The request that generated this response
    pub original_request: GetQuoteRequest,
    /// When this response was received and saved
    pub saved_at: DateTime<Utc>,
    /// File path where this was saved
    pub file_path: PathBuf,
    /// Optional description/notes
    pub description: Option<String>,
}

/// Batch test results for multiple intents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTestResults {
    /// Test results for each intent
    pub results: Vec<QuoteTestResult>,
    /// When the batch test was run
    pub tested_at: DateTime<Utc>,
    /// File path where results were saved
    pub file_path: PathBuf,
    /// Overall statistics
    pub statistics: BatchTestStatistics,
}

/// Individual quote test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteTestResult {
    /// The intent that was tested
    pub request: GetQuoteRequest,
    /// Quote response if successful
    pub response: Option<GetQuoteResponse>,
    /// Error message if failed
    pub error: Option<String>,
    /// Time taken for the request
    pub duration_ms: u64,
    /// Test status
    pub status: QuoteTestStatus,
}

/// Status of a quote test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuoteTestStatus {
    Success,
    Failed,
    Timeout,
    InvalidRequest,
}

/// Statistics for batch testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTestStatistics {
    /// Total number of tests
    pub total: usize,
    /// Number of successful tests
    pub successful: usize,
    /// Number of failed tests
    pub failed: usize,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Total test duration
    pub total_duration_ms: u64,
}