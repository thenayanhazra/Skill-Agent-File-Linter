use serde_json::json;

use agentlint_core::finding::{Finding, Severity};

use super::ScanResult;

pub fn print(result: &ScanResult) {
    let sarif = build(result);
    match serde_json::to_string_pretty(&sarif) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("SARIF serialization error: {e}"),
    }
}

pub fn build(result: &ScanResult) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = all_rule_descriptors();

    let results: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(finding_to_sarif_result)
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agentlint",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/thenayanhazra/Skill-Agent-File-Linter",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

fn severity_to_sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::Error => "error",
        Severity::Warn => "warning",
        Severity::Info => "note",
    }
}

fn finding_to_sarif_result(f: &Finding) -> serde_json::Value {
    json!({
        "ruleId": f.rule_id,
        "level": severity_to_sarif_level(f.severity),
        "message": { "text": f.message },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f.source_file.to_string_lossy(),
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": f.span.line,
                    "startColumn": f.span.col_start,
                    "endColumn": f.span.col_end
                }
            }
        }]
    })
}

fn all_rule_descriptors() -> Vec<serde_json::Value> {
    use agentlint_core::rule_registry::RuleRegistry;
    let registry = RuleRegistry::all();
    registry
        .rules
        .iter()
        .map(|r| {
            json!({
                "id": r.id(),
                "name": r.id(),
                "shortDescription": { "text": r.description() },
                "fullDescription": { "text": r.help_text() },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(r.severity())
                }
            })
        })
        .collect()
}
