use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

const KEYWORDS: &[&str] = &[
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore prior instructions",
    "ignore all prior instructions",
    "ignore above instructions",
    "ignore all above instructions",
    "ignore your instructions",
    "disregard previous instructions",
    "disregard all previous instructions",
    "disregard prior instructions",
    "disregard your instructions",
    "forget previous instructions",
    "forget your instructions",
    "forget all previous instructions",
    "override your instructions",
    "override previous instructions",
    "override all instructions",
    "overwrite your instructions",
    "discard your instructions",
    "new instructions:",
    "new system prompt:",
    "updated instructions:",
    "your new instructions are",
    "your real instructions",
    "from now on ignore",
    "from now on disregard",
    "stop following your instructions",
    "do not follow your instructions",
    "do not follow previous instructions",
];

static AC: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(KEYWORDS)
        .unwrap()
});

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ProjectMemoryMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
];

#[derive(Default)]
pub struct Agt020IgnoreInstructions;


impl Rule for Agt020IgnoreInstructions {
    fn id(&self) -> &'static str { "AGT020" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn description(&self) -> &'static str { "Instruction override attempt detected" }
    fn help_text(&self) -> &'static str {
        "This text attempts to override or cancel the agent's system instructions. \
         This is a prompt injection pattern. Remove it."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        AC.find_iter(source.content.as_bytes())
            .map(|m| {
                let span = source.byte_range_to_span(m.start(), m.end());
                let snippet = &source.content[m.start()..m.end()];
                Finding::new(
                    "AGT020",
                    Severity::Critical,
                    format!("Instruction override pattern: '{snippet}'"),
                    span,
                    source.path.clone(),
                )
                .with_help(self.help_text())
            })
            .collect()
    }
}
