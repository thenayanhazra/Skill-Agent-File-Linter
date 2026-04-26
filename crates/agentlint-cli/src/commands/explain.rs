use agentlint_core::{finding::Severity, rule_registry::RuleRegistry};
use owo_colors::OwoColorize;

pub fn run(rule_id: &str) {
    let registry = RuleRegistry::all();
    match registry.rules.iter().find(|r| r.id().eq_ignore_ascii_case(rule_id)) {
        None => {
            eprintln!("No rule found with ID: {rule_id}");
            eprintln!("Run `agentlint list-rules` to see all available rules.");
        }
        Some(rule) => {
            println!("{}", format!("Rule {}", rule.id()).bold());
            println!("  Severity:    {}", format_severity(rule.severity()));
            println!("  Autofixable: {}", if rule.is_autofixable() { "yes".green().to_string() } else { "no".dimmed().to_string() });
            println!();
            println!("{}", "Description:".bold());
            println!("  {}", rule.description());
            println!();
            println!("{}", "Details:".bold());
            let help = rule.help_text();
            for line in textwrap_lines(help, 72) {
                println!("  {line}");
            }
            println!();
            println!("  Applies to: {}", format_types(rule.applicable_to()));
        }
    }
}

fn format_severity(s: Severity) -> String {
    match s {
        Severity::Critical => "critical".red().bold().to_string(),
        Severity::Error    => "error".red().to_string(),
        Severity::Warn     => "warn".yellow().to_string(),
        Severity::Info     => "info".cyan().to_string(),
    }
}

fn format_types(types: &[agentlint_core::file_type::FileType]) -> String {
    types.iter().map(|t| format!("{t:?}")).collect::<Vec<_>>().join(", ")
}

fn textwrap_lines(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        if current.len() + word.len() + 1 > width && !current.is_empty() {
            lines.push(current.clone());
            current.clear();
        } else if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() { lines.push(current); }
    lines
}
