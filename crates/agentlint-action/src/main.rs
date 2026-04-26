/// GitHub Actions wrapper for agentlint.
/// Reads inputs from environment variables set by actions/checkout and the action.yml.
use std::env;
use agentlint_core::{
    engine::{scan_file, ScanOptions},
    file_type::FileType,
    finding::Severity,
    rule_registry::RuleRegistry,
    source_file::SourceFile,
};

fn main() {
    let paths_input = env::var("INPUT_PATHS").unwrap_or_else(|_| ".".to_string());
    let severity_input = env::var("INPUT_SEVERITY").unwrap_or_else(|_| "warn".to_string());
    let sarif_output = env::var("INPUT_SARIF-OUTPUT").unwrap_or_else(|_| "results.sarif".to_string());

    let min_severity: Severity = severity_input.parse().unwrap_or(Severity::Warn);

    let registry = RuleRegistry::all();
    let opts = ScanOptions { min_severity };
    let mut all_findings = Vec::new();
    let mut files_scanned = 0usize;

    let walker = ignore::WalkBuilder::new(".")
        .hidden(false)
        .git_ignore(true)
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }

        // Check if path matches any of the input patterns
        let path_str = path.to_string_lossy();
        let in_scope = paths_input.split_whitespace().any(|p| {
            p == "." || path_str.starts_with(p) || path_str == p
        });
        if !in_scope { continue; }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let maybe = matches!(ext, "md" | "json")
            || matches!(file_name, ".cursorrules" | ".clinerules" | ".windsurfrules");
        if !maybe { continue; }

        match SourceFile::read(path, None) {
            Ok(source) if source.file_type != FileType::Unknown => {
                let findings = scan_file(&source, &registry, &opts);
                for f in &findings {
                    // Emit GitHub Actions annotations
                    let level = match f.severity {
                        Severity::Critical | Severity::Error => "error",
                        Severity::Warn => "warning",
                        Severity::Info => "notice",
                    };
                    println!(
                        "::{level} file={},line={},col={}::[{}] {}",
                        f.source_file.display(),
                        f.span.line,
                        f.span.col_start,
                        f.rule_id,
                        f.message
                    );
                }
                all_findings.extend(findings);
                files_scanned += 1;
            }
            _ => {}
        }
    }

    // Write SARIF
    let sarif_result = build_sarif_result(files_scanned, &all_findings);
    let sarif_json = serde_json::to_string_pretty(&sarif_result).unwrap_or_default();
    if let Err(e) = std::fs::write(&sarif_output, &sarif_json) {
        eprintln!("Warning: could not write SARIF to {sarif_output}: {e}");
    }

    // Output variables
    println!("::set-output name=findings-count::{}", all_findings.len());
    println!("::set-output name=files-scanned::{files_scanned}");

    let exit_code = if all_findings.is_empty() { 0 } else { 1 };
    std::process::exit(exit_code);
}

fn build_sarif_result(files_scanned: usize, findings: &[agentlint_core::finding::Finding]) -> serde_json::Value {
    use agentlint_core::finding::Severity;
    use serde_json::json;

    let results: Vec<serde_json::Value> = findings.iter().map(|f| {
        let level = match f.severity {
            Severity::Critical | Severity::Error => "error",
            Severity::Warn => "warning",
            Severity::Info => "note",
        };
        json!({
            "ruleId": f.rule_id,
            "level": level,
            "message": { "text": f.message },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.source_file.to_string_lossy(),
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": f.span.line,
                        "startColumn": f.span.col_start
                    }
                }
            }]
        })
    }).collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agentlint",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/thenayanhazra/Skill-Agent-File-Linter"
                }
            },
            "results": results,
            "properties": {
                "filesScanned": files_scanned
            }
        }]
    })
}
