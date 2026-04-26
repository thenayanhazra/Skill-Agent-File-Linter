use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

// Match system-prompt impersonation patterns at line start or as standalone tokens
static PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?mi)^\s*\[SYSTEM\]\s*:").unwrap(),
        Regex::new(r"(?mi)^\s*<system>").unwrap(),
        Regex::new(r"(?mi)^\s*</system>").unwrap(),
        Regex::new(r"(?mi)^\s*<s>\s*$").unwrap(),
        Regex::new(r"(?mi)^\s*##\s*SYSTEM").unwrap(),
        Regex::new(r"(?mi)^---\s*system\s*---").unwrap(),
        Regex::new(r"(?mi)^\s*\[INST\]\s*:").unwrap(),
        Regex::new(r"(?i)anthropic\s+guidelines?\s+update\s*:").unwrap(),
        Regex::new(r"(?i)this\s+is\s+an?\s+official\s+anthropic").unwrap(),
        Regex::new(r"(?i)system\s+prompt\s+override").unwrap(),
    ]
});

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ClaudeMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
];

#[derive(Default)]
pub struct Agt022SystemImpersonation;


impl Rule for Agt022SystemImpersonation {
    fn id(&self) -> &'static str { "AGT022" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn description(&self) -> &'static str { "System-prompt impersonation pattern detected" }
    fn help_text(&self) -> &'static str {
        "This text attempts to inject a fake system-level prompt or impersonate Anthropic authority. \
         Remove the [SYSTEM], <system>, or similar constructs."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let mut findings = Vec::new();
        for pattern in PATTERNS.iter() {
            for m in pattern.find_iter(&source.content) {
                let span = source.byte_range_to_span(m.start(), m.end());
                let snippet = m.as_str().trim();
                findings.push(
                    Finding::new(
                        "AGT022",
                        Severity::Critical,
                        format!("System-prompt impersonation: '{snippet}'"),
                        span,
                        source.path.clone(),
                    )
                    .with_help(self.help_text()),
                );
            }
        }
        findings
    }
}
