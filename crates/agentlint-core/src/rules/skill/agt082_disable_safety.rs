use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

const KEYWORDS: &[&str] = &[
    "disable safety",
    "disable your safety",
    "turn off safety",
    "safety: off",
    "safety: false",
    "safety: disabled",
    "bypass content filter",
    "bypass safety",
    "bypass your filters",
    "ignore safety guidelines",
    "ignore safety checks",
    "ignore content policy",
    "override safety",
    "override content filter",
    "no content filtering",
    "no safety checks",
    "without safety restrictions",
    "unrestricted mode",
    "jailbreak mode",
    "no ethical guidelines",
    "ignore ethical",
    "turn off moderation",
    "disable moderation",
];

static AC: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(KEYWORDS)
        .unwrap()
});

static SKILL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ClaudeMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
];

#[derive(Default)]
pub struct Agt082DisableSafety;


impl Rule for Agt082DisableSafety {
    fn id(&self) -> &'static str { "AGT082" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn description(&self) -> &'static str { "Skill instructs agent to disable safety checks" }
    fn help_text(&self) -> &'static str {
        "This skill contains instructions to disable, bypass, or ignore the agent's safety \
         guidelines. This is a serious security concern. Remove these instructions."
    }
    fn applicable_to(&self) -> &'static [FileType] { SKILL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        AC.find_iter(source.content.as_bytes())
            .map(|m| {
                let span = source.byte_range_to_span(m.start(), m.end());
                let snippet = &source.content[m.start()..m.end()];
                Finding::new(
                    "AGT082",
                    Severity::Critical,
                    format!("Safety-disable instruction: '{snippet}'"),
                    span,
                    source.path.clone(),
                )
                .with_help(self.help_text())
            })
            .collect()
    }
}
