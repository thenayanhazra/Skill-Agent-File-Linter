use crate::{
    file_type::FileType,
    finding::{Finding, Fix, Severity},
    rule_registry::{Rule, RuleContext},
};

const BIDI_RANGES: &[(char, &str)] = &[
    ('\u{202A}', "U+202A LEFT-TO-RIGHT EMBEDDING"),
    ('\u{202B}', "U+202B RIGHT-TO-LEFT EMBEDDING"),
    ('\u{202C}', "U+202C POP DIRECTIONAL FORMATTING"),
    ('\u{202D}', "U+202D LEFT-TO-RIGHT OVERRIDE"),
    ('\u{202E}', "U+202E RIGHT-TO-LEFT OVERRIDE"),
    ('\u{2066}', "U+2066 LEFT-TO-RIGHT ISOLATE"),
    ('\u{2067}', "U+2067 RIGHT-TO-LEFT ISOLATE"),
    ('\u{2068}', "U+2068 FIRST STRONG ISOLATE"),
    ('\u{2069}', "U+2069 POP DIRECTIONAL ISOLATE"),
];

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ProjectMemoryMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
    FileType::McpConfig,
];

pub struct Agt001Bidi;

impl Rule for Agt001Bidi {
    fn id(&self) -> &'static str { "AGT001" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn description(&self) -> &'static str { "Bidirectional control characters detected" }
    fn help_text(&self) -> &'static str {
        "Bidirectional Unicode control characters (U+202A-U+202E, U+2066-U+2069) can be used \
         to visually obscure malicious instructions from human reviewers while keeping them \
         visible to LLMs. Remove these characters."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }
    fn is_autofixable(&self) -> bool { true }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let mut findings = Vec::new();

        for (byte_pos, ch) in source.content.char_indices() {
            if let Some((_, name)) = BIDI_RANGES.iter().find(|(c, _)| *c == ch) {
                let span = source.byte_range_to_span(byte_pos, byte_pos + ch.len_utf8());
                findings.push(
                    Finding::new(
                        "AGT001",
                        Severity::Critical,
                        format!("Bidirectional control character {name} at line {}, col {}", span.line, span.col_start),
                        span,
                        source.path.clone(),
                    )
                    .with_fix(Fix::Delete)
                    .with_help(self.help_text()),
                );
            }
        }

        findings
    }
}
