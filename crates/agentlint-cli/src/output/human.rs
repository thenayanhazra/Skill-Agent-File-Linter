use std::collections::BTreeMap;
use std::path::PathBuf;

use agentlint_core::finding::{Finding, Severity};
use owo_colors::OwoColorize;

use super::ScanResult;

pub fn print(result: &ScanResult) {
    if result.findings.is_empty() {
        println!("{}", "No findings.".green());
        return;
    }

    // Group by file
    let mut by_file: BTreeMap<&PathBuf, Vec<&Finding>> = BTreeMap::new();
    for f in &result.findings {
        by_file.entry(&f.source_file).or_default().push(f);
    }

    for (path, findings) in &by_file {
        println!("\n{}", format!("── {} ──", path.display()).bold());
        for f in findings {
            print_finding(f);
        }
    }

    let counts = count_by_severity(&result.findings);
    println!();
    println!(
        "Found {} finding(s) in {} file(s): {} critical, {} error, {} warn, {} info",
        result.findings.len().bold(),
        by_file.len().bold(),
        counts[3].to_string().red().bold(),
        counts[2].to_string().red(),
        counts[1].to_string().yellow(),
        counts[0].to_string().cyan(),
    );
}

fn print_finding(f: &Finding) {
    let severity_str = match f.severity {
        Severity::Critical => format!("critical[{}]", f.rule_id).red().bold().to_string(),
        Severity::Error    => format!("error[{}]", f.rule_id).red().to_string(),
        Severity::Warn     => format!("warn[{}]", f.rule_id).yellow().to_string(),
        Severity::Info     => format!("info[{}]", f.rule_id).cyan().to_string(),
    };

    println!("  {severity_str}: {}", f.message);
    println!(
        "   {} {}:{}:{}",
        "-->".dimmed(),
        f.source_file.display(),
        f.span.line,
        f.span.col_start
    );

    if let Some(help) = f.help {
        // Wrap help text at 80 chars
        let wrapped = textwrap(help, 74);
        println!("   {} {}", "help:".dimmed(), wrapped);
    }

    if f.fix.is_some() {
        println!("   {} run `agentlint fix` to auto-fix", "fix available:".green().dimmed());
    }
}

fn count_by_severity(findings: &[Finding]) -> [usize; 4] {
    let mut counts = [0usize; 4];
    for f in findings {
        match f.severity {
            Severity::Info     => counts[0] += 1,
            Severity::Warn     => counts[1] += 1,
            Severity::Error    => counts[2] += 1,
            Severity::Critical => counts[3] += 1,
        }
    }
    counts
}

fn textwrap(s: &str, width: usize) -> String {
    if s.len() <= width {
        return s.to_owned();
    }
    let mut result = String::new();
    let mut line_len = 0;
    for word in s.split_whitespace() {
        if line_len + word.len() + 1 > width && line_len > 0 {
            result.push('\n');
            result.push_str("         ");
            line_len = 0;
        } else if line_len > 0 {
            result.push(' ');
            line_len += 1;
        }
        result.push_str(word);
        line_len += word.len();
    }
    result
}
