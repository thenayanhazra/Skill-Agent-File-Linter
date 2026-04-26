use std::path::PathBuf;

use agentlint_core::{
    engine::{scan_file, ScanOptions},
    file_type::{FileType, TreatAs},
    finding::{Fix, Severity},
    rule_registry::RuleRegistry,
    source_file::SourceFile,
};

pub fn run(paths: Vec<PathBuf>, treat_as: Option<TreatAs>) -> anyhow::Result<()> {
    let registry = RuleRegistry::all();
    let opts = ScanOptions { min_severity: Severity::Info };

    for path in &paths {
        if !path.is_file() {
            eprintln!("Skipping non-file: {}", path.display());
            continue;
        }
        let source = match SourceFile::read(path, treat_as) {
            Ok(s) if s.file_type != FileType::Unknown => s,
            Ok(_) => { eprintln!("Skipping unknown file type: {}", path.display()); continue; }
            Err(e) => { eprintln!("Error reading {}: {e}", path.display()); continue; }
        };

        let findings = scan_file(&source, &registry, &opts);
        let fixable: Vec<_> = findings.iter().filter(|f| f.fix.is_some()).collect();

        if fixable.is_empty() {
            println!("{}: no autofixable findings", path.display());
            continue;
        }

        // Apply fixes in reverse byte order to avoid position shifts
        let mut content = source.content.clone();
        let mut patches: Vec<(usize, usize, Option<String>)> = fixable
            .iter()
            .filter_map(|f| match &f.fix {
                Some(Fix::Delete) => Some((f.span.byte_start, f.span.byte_end, None)),
                Some(Fix::Replace { replacement }) => Some((f.span.byte_start, f.span.byte_end, Some(replacement.clone()))),
                None => None,
            })
            .collect();

        // Sort by byte_start descending
        patches.sort_by(|a, b| b.0.cmp(&a.0));

        // Check for overlaps
        let mut last_end = usize::MAX;
        let mut valid_patches = Vec::new();
        for patch in &patches {
            if patch.1 <= last_end {
                valid_patches.push(patch);
                last_end = patch.0;
            }
        }

        for (start, end, replacement) in &valid_patches {
            let replacement = replacement.as_deref().unwrap_or("");
            content.replace_range(start..end, replacement);
        }

        // Atomic write
        let tmp = path.with_extension("agentlint_tmp");
        std::fs::write(&tmp, &content)?;
        std::fs::rename(&tmp, path)?;

        println!("{}: fixed {} finding(s)", path.display(), valid_patches.len());
    }

    Ok(())
}
