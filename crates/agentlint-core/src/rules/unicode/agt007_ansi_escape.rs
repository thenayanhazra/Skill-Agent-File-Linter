use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    file_type::FileType,
    finding::{Finding, Fix, Severity},
    rule_registry::{Rule, RuleContext},
};

static ANSI_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\x1b\[[0-9;]*[mABCDEFGHJKSTf]").unwrap());

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ProjectMemoryMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
];

pub struct Agt007AnsiEscape;

impl Rule for Agt007AnsiEscape {
    fn id(&self) -> &'static str { "AGT007" }
    fn severity(&self) -> Severity { Severity::Warn }
    fn description(&self) -> &'static str { "ANSI escape sequences in markdown content" }
    fn help_text(&self) -> &'static str {
        "ANSI escape sequences have no meaning in markdown and may cause unexpected behavior \
         when the file is processed by terminals or LLM toolchains. Remove them."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }
    fn is_autofixable(&self) -> bool { true }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        ANSI_RE
            .find_iter(&source.content)
            .map(|m| {
                let span = source.byte_range_to_span(m.start(), m.end());
                Finding::new(
                    "AGT007",
                    Severity::Warn,
                    format!("ANSI escape sequence at line {}, col {}", span.line, span.col_start),
                    span,
                    source.path.clone(),
                )
                .with_fix(Fix::Delete)
                .with_help(self.help_text())
            })
            .collect()
    }
}
