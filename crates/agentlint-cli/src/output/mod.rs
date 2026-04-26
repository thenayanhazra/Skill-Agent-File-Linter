pub mod human;
pub mod json_out;
pub mod sarif;

use agentlint_core::finding::Finding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub version:       &'static str,
    pub files_scanned: usize,
    pub findings:      Vec<Finding>,
}

impl ScanResult {
    pub fn new(files_scanned: usize, findings: Vec<Finding>) -> Self {
        Self { version: "1", files_scanned, findings }
    }
}
