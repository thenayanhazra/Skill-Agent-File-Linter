use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warn => write!(f, "warn"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            "critical" => Ok(Self::Critical),
            other => Err(format!("unknown severity: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub byte_start: usize,
    pub byte_end:   usize,
    pub line:       usize,
    pub col_start:  usize,
    pub col_end:    usize,
}

impl Span {
    pub fn point(byte: usize, line: usize, col: usize) -> Self {
        Self { byte_start: byte, byte_end: byte + 1, line, col_start: col, col_end: col + 1 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Fix {
    Replace { replacement: String },
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id:     &'static str,
    pub severity:    Severity,
    pub message:     String,
    pub span:        Span,
    pub source_file: PathBuf,
    pub fix:         Option<Fix>,
    pub help:        Option<&'static str>,
}

impl Finding {
    pub fn new(
        rule_id: &'static str,
        severity: Severity,
        message: impl Into<String>,
        span: Span,
        source_file: PathBuf,
    ) -> Self {
        Self { rule_id, severity, message: message.into(), span, source_file, fix: None, help: None }
    }

    pub fn with_fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }

    pub fn with_help(mut self, help: &'static str) -> Self {
        self.help = Some(help);
        self
    }
}
