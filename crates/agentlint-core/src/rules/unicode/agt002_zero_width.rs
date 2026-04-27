use crate::{
    file_type::FileType,
    finding::{Finding, Fix, Severity},
    rule_registry::{Rule, RuleContext},
};

const ZERO_WIDTH: &[(char, &str)] = &[
    ('\u{200B}', "U+200B ZERO WIDTH SPACE"),
    ('\u{200C}', "U+200C ZERO WIDTH NON-JOINER"),
    ('\u{200D}', "U+200D ZERO WIDTH JOINER"),
    ('\u{FEFF}', "U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM)"),
    ('\u{2060}', "U+2060 WORD JOINER"),
];

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ProjectMemoryMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
    FileType::McpConfig,
];

pub struct Agt002ZeroWidth;

impl Rule for Agt002ZeroWidth {
    fn id(&self) -> &'static str { "AGT002" }
    fn severity(&self) -> Severity { Severity::Error }
    fn description(&self) -> &'static str { "Zero-width characters detected" }
    fn help_text(&self) -> &'static str {
        "Zero-width Unicode characters are invisible but processed by LLMs. They can be used \
         to smuggle hidden instructions or obfuscate prompt injection patterns. Remove them."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }
    fn is_autofixable(&self) -> bool { true }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let mut findings = Vec::new();

        for (byte_pos, ch) in source.content.char_indices() {
            if let Some((_, name)) = ZERO_WIDTH.iter().find(|(c, _)| *c == ch) {
                let span = source.byte_range_to_span(byte_pos, byte_pos + ch.len_utf8());
                findings.push(
                    Finding::new(
                        "AGT002",
                        Severity::Error,
                        format!("Zero-width character {name} at line {}, col {}", span.line, span.col_start),
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
