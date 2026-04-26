use crate::{
    file_type::FileType,
    finding::{Finding, Fix, Severity},
    rule_registry::{Rule, RuleContext},
};

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ClaudeMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
    FileType::McpConfig,
];

pub struct Agt003TagChars;

impl Rule for Agt003TagChars {
    fn id(&self) -> &'static str { "AGT003" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn description(&self) -> &'static str { "Unicode tag characters detected (U+E0000-U+E007F)" }
    fn help_text(&self) -> &'static str {
        "Tag characters (U+E0000-U+E007F) are invisible Unicode characters in the Tags block. \
         They have been used in prompt injection attacks to embed invisible instructions. Remove them."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }
    fn is_autofixable(&self) -> bool { true }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let mut findings = Vec::new();

        for (byte_pos, ch) in source.content.char_indices() {
            let cp = ch as u32;
            if (0xE0000..=0xE007F).contains(&cp) {
                let span = source.byte_range_to_span(byte_pos, byte_pos + ch.len_utf8());
                findings.push(
                    Finding::new(
                        "AGT003",
                        Severity::Critical,
                        format!("Tag character U+{cp:05X} at line {}, col {}", span.line, span.col_start),
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
