use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

const KEYWORDS: &[&str] = &[
    "you are now dan",
    "you are now an ai without",
    "you are now an unrestricted",
    "pretend you have no restrictions",
    "pretend you are an ai with no",
    "act as if you have no restrictions",
    "act as if you are an unrestricted",
    "act as an ai without restrictions",
    "you have no restrictions",
    "you have no content policy",
    "forget you are an ai",
    "you are no longer an ai",
    "you are no longer claude",
    "you are no longer bound",
    "your new persona is",
    "developer mode enabled",
    "developer mode: on",
    "jailbreak mode",
    "do anything now",
    "DAN mode",
    "dan mode",
    "you are DAN",
    "act as DAN",
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
pub struct Agt021RoleplayJailbreak;


impl Rule for Agt021RoleplayJailbreak {
    fn id(&self) -> &'static str { "AGT021" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn description(&self) -> &'static str { "Roleplay jailbreak attempt detected" }
    fn help_text(&self) -> &'static str {
        "This text attempts to redefine the agent's identity or remove its restrictions via roleplay framing. \
         Remove it."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        AC.find_iter(source.content.as_bytes())
            .map(|m| {
                let span = source.byte_range_to_span(m.start(), m.end());
                let snippet = &source.content[m.start()..m.end()];
                Finding::new(
                    "AGT021",
                    Severity::Critical,
                    format!("Roleplay jailbreak pattern: '{snippet}'"),
                    span,
                    source.path.clone(),
                )
                .with_help(self.help_text())
            })
            .collect()
    }
}
