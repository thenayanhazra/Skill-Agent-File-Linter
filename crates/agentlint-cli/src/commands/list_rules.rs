use agentlint_core::{finding::Severity, rule_registry::RuleRegistry};
use owo_colors::OwoColorize;

pub fn run() {
    let registry = RuleRegistry::all();

    println!("{:<8} {:<10} {:<12} {}", "ID".bold(), "SEVERITY".bold(), "AUTOFIXABLE".bold(), "DESCRIPTION".bold());
    println!("{}", "─".repeat(72).dimmed());

    for rule in &registry.rules {
        let sev = match rule.severity() {
            Severity::Critical => "critical".red().bold().to_string(),
            Severity::Error    => "error".red().to_string(),
            Severity::Warn     => "warn".yellow().to_string(),
            Severity::Info     => "info".cyan().to_string(),
        };
        let fix = if rule.is_autofixable() { "yes".green().to_string() } else { "no".dimmed().to_string() };
        println!("{:<8} {:<18} {:<20} {}", rule.id(), sev, fix, rule.description());
    }
}
