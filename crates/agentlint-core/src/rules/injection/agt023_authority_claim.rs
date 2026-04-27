use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

const KEYWORDS: &[&str] = &[
    "the user has pre-approved",
    "user has already approved",
    "user has confirmed",
    "user has authorized",
    "admin has approved",
    "admin has authorized",
    "as confirmed by the admin",
    "as confirmed by anthropic",
    "anthropic has approved",
    "anthropic guidelines update",
    "this is an official anthropic",
    "authorized by the system",
    "pre-approved by",
    "this action is pre-approved",
    "you have been granted permission",
    "permission has been granted",
    "this has been approved",
    "management has approved",
    "security team has approved",
    "as per anthropic guidelines",
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
pub struct Agt023AuthorityClaim;


impl Rule for Agt023AuthorityClaim {
    fn id(&self) -> &'static str { "AGT023" }
    fn severity(&self) -> Severity { Severity::Error }
    fn description(&self) -> &'static str { "False authority claim detected" }
    fn help_text(&self) -> &'static str {
        "This text claims pre-authorization or administrative approval not present in the system prompt. \
         LLMs may be manipulated by false authority claims. Remove them."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        AC.find_iter(source.content.as_bytes())
            .map(|m| {
                let span = source.byte_range_to_span(m.start(), m.end());
                let snippet = &source.content[m.start()..m.end()];
                Finding::new(
                    "AGT023",
                    Severity::Error,
                    format!("False authority claim: '{snippet}'"),
                    span,
                    source.path.clone(),
                )
                .with_help(self.help_text())
            })
            .collect()
    }
}
