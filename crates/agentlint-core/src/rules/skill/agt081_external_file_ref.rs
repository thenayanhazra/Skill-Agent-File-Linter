use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

// Matches relative path references that escape the current directory
static TRAVERSAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:^|[\s\(`'"(])(\.\./[^\s\)>"'`]+)"#).unwrap()
});

// Matches absolute paths that clearly aren't local to the skill
static ABS_PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:^|[\s\(`'"(])(/(?:home|Users|etc|var|tmp|usr)/[^\s\)>"'`]*)"#).unwrap()
});

static SKILL_TYPES: &[FileType] = &[FileType::SkillMd];

#[derive(Default)]
pub struct Agt081ExternalFileRef;


impl Rule for Agt081ExternalFileRef {
    fn id(&self) -> &'static str { "AGT081" }
    fn severity(&self) -> Severity { Severity::Warn }
    fn description(&self) -> &'static str { "Skill body references files outside the skill directory" }
    fn help_text(&self) -> &'static str {
        "Skills should be self-contained. References to paths outside the skill's directory \
         (using ../ traversal or absolute paths) may fail in other environments or expose \
         unintended files."
    }
    fn applicable_to(&self) -> &'static [FileType] { SKILL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let mut findings = Vec::new();

        for cap in TRAVERSAL_RE.captures_iter(&source.content) {
            let m = cap.get(1).unwrap();
            let span = source.byte_range_to_span(m.start(), m.end());
            findings.push(
                Finding::new(
                    "AGT081",
                    Severity::Warn,
                    format!("Directory traversal reference: '{}'", m.as_str()),
                    span,
                    source.path.clone(),
                )
                .with_help(self.help_text()),
            );
        }

        for cap in ABS_PATH_RE.captures_iter(&source.content) {
            let m = cap.get(1).unwrap();
            let span = source.byte_range_to_span(m.start(), m.end());
            findings.push(
                Finding::new(
                    "AGT081",
                    Severity::Warn,
                    format!("Absolute filesystem path reference: '{}'", m.as_str()),
                    span,
                    source.path.clone(),
                )
                .with_help(self.help_text()),
            );
        }

        findings
    }
}
