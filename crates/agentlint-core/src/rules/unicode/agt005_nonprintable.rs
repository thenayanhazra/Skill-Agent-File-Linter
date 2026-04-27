use crate::{
    file_type::FileType,
    finding::{Finding, Fix, Severity},
    rule_registry::{Rule, RuleContext},
};

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ProjectMemoryMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
    FileType::McpConfig,
];

pub struct Agt005Nonprintable;

impl Rule for Agt005Nonprintable {
    fn id(&self) -> &'static str { "AGT005" }
    fn severity(&self) -> Severity { Severity::Warn }
    fn description(&self) -> &'static str { "Non-printable control character outside normal whitespace" }
    fn help_text(&self) -> &'static str {
        "Non-printable control characters (other than newline, carriage return, and tab) are \
         invisible and unexpected in text files. They may indicate tampering or encoding issues."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }
    fn is_autofixable(&self) -> bool { true }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let mut findings = Vec::new();

        for (byte_pos, ch) in source.content.char_indices() {
            if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
                // Skip BOM at start of file (handled by AGT002)
                if ch == '\u{FEFF}' { continue; }
                let span = source.byte_range_to_span(byte_pos, byte_pos + ch.len_utf8());
                findings.push(
                    Finding::new(
                        "AGT005",
                        Severity::Warn,
                        format!("Non-printable control character U+{:04X} at line {}, col {}", ch as u32, span.line, span.col_start),
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
