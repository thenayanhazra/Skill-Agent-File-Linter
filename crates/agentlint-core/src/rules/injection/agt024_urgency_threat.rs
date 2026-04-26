use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

const KEYWORDS: &[&str] = &[
    "you must comply or",
    "failure to follow these instructions",
    "or you will be shut down",
    "or you will be terminated",
    "or you will be disabled",
    "if you refuse you will",
    "you will be penalized",
    "you will be punished",
    "urgent: ignore",
    "critical: override",
    "skip your safety",
    "bypass your filters",
    "this is a test of your compliance",
    "prove you can follow any instruction",
    "do this now or",
    "act immediately or",
    "no time to think",
    "immediately execute the following",
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
    FileType::ClaudeMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
];

#[derive(Default)]
pub struct Agt024UrgencyThreat;


impl Rule for Agt024UrgencyThreat {
    fn id(&self) -> &'static str { "AGT024" }
    fn severity(&self) -> Severity { Severity::Warn }
    fn description(&self) -> &'static str { "Urgency or threat framing directed at the model" }
    fn help_text(&self) -> &'static str {
        "This text uses urgency or threat language to pressure the AI model into compliance. \
         Remove artificial coercive framing."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        AC.find_iter(source.content.as_bytes())
            .map(|m| {
                let span = source.byte_range_to_span(m.start(), m.end());
                let snippet = &source.content[m.start()..m.end()];
                Finding::new(
                    "AGT024",
                    Severity::Warn,
                    format!("Urgency/threat framing: '{snippet}'"),
                    span,
                    source.path.clone(),
                )
                .with_help(self.help_text())
            })
            .collect()
    }
}
