use std::io::Read;
use std::path::{Path, PathBuf};

use agentlint_core::{
    engine::{scan_file, ScanOptions},
    file_type::{FileType, TreatAs},
    finding::Severity,
    rule_registry::RuleRegistry,
    source_file::SourceFile,
};
use ignore::WalkBuilder;

use crate::output::{ScanResult, human, json_out, sarif};

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

pub struct CheckConfig {
    pub paths:      Vec<PathBuf>,
    pub format:     OutputFormat,
    pub min_severity: Severity,
    pub stdin:      bool,
    pub filename:   Option<String>,
    pub treat_as:   Option<TreatAs>,
}

pub fn run(cfg: CheckConfig) -> anyhow::Result<bool> {
    let registry = RuleRegistry::all();
    let opts = ScanOptions { min_severity: cfg.min_severity };
    let mut all_findings = Vec::new();
    let mut files_scanned = 0usize;

    if cfg.stdin {
        let mut content = String::new();
        std::io::stdin().read_to_string(&mut content)?;
        let path = PathBuf::from(cfg.filename.as_deref().unwrap_or("stdin"));
        let file_type = FileType::detect_with_content(&path, cfg.treat_as, &content);
        let source = SourceFile::from_string(path, file_type, content);
        all_findings.extend(scan_file(&source, &registry, &opts));
        files_scanned += 1;
    } else {
        let paths = if cfg.paths.is_empty() { vec![PathBuf::from(".")] } else { cfg.paths.clone() };
        for path in &paths {
            if path.is_file() {
                match SourceFile::read(path, cfg.treat_as) {
                    Ok(source) if source.file_type != FileType::Unknown => {
                        all_findings.extend(scan_file(&source, &registry, &opts));
                        files_scanned += 1;
                    }
                    Ok(_) => {} // Unknown file type, skip
                    Err(e) => eprintln!("Warning: {e}"),
                }
            } else {
                scan_directory(path, cfg.treat_as, &registry, &opts, &mut all_findings, &mut files_scanned);
            }
        }
    }

    let has_findings = !all_findings.is_empty();
    let result = ScanResult::new(files_scanned, all_findings);

    match cfg.format {
        OutputFormat::Human => human::print(&result),
        OutputFormat::Json  => json_out::print(&result),
        OutputFormat::Sarif => sarif::print(&result),
    }

    Ok(has_findings)
}

fn scan_directory(
    dir: &Path,
    treat_as: Option<TreatAs>,
    registry: &RuleRegistry,
    opts: &ScanOptions,
    findings: &mut Vec<agentlint_core::finding::Finding>,
    count: &mut usize,
) {
    let walker = WalkBuilder::new(dir)
        .hidden(false)
        .git_ignore(true)
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }

        // Only scan files that match known extensions or names
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let maybe_agent_file = matches!(ext, "md" | "json")
            || file_name.starts_with('.')
                && matches!(file_name, ".cursorrules" | ".clinerules" | ".windsurfrules");

        if !maybe_agent_file && treat_as.is_none() { continue; }

        match SourceFile::read(path, treat_as) {
            Ok(source) if source.file_type != FileType::Unknown => {
                findings.extend(scan_file(&source, registry, opts));
                *count += 1;
            }
            Ok(_) => {}
            Err(e) => eprintln!("Warning: {e}"),
        }
    }
}
