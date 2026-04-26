use crate::{
    finding::{Finding, Severity},
    parser::ParsedFile,
    rule_registry::RuleRegistry,
    source_file::SourceFile,
};

pub struct ScanOptions {
    pub min_severity: Severity,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { min_severity: Severity::Info }
    }
}

/// Scan a single source file and return all findings at or above the minimum severity.
pub fn scan_file(source: &SourceFile, registry: &RuleRegistry, opts: &ScanOptions) -> Vec<Finding> {
    let parsed = ParsedFile::parse(source);
    let ctx = crate::rule_registry::RuleContext { source, parsed: &parsed };

    let mut findings: Vec<Finding> = registry
        .rules
        .iter()
        .filter(|r| r.severity() >= opts.min_severity)
        .filter(|r| r.applicable_to().contains(&source.file_type))
        .flat_map(|r| r.check(&ctx))
        .filter(|f| f.severity >= opts.min_severity)
        .collect();

    findings.sort_by(|a, b| {
        a.span.line.cmp(&b.span.line).then(a.span.col_start.cmp(&b.span.col_start))
    });

    findings
}
