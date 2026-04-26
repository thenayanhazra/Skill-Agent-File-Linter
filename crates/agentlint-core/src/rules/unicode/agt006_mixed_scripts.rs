use unicode_script::{Script, UnicodeScript};

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
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

pub struct Agt006MixedScripts;

impl Rule for Agt006MixedScripts {
    fn id(&self) -> &'static str { "AGT006" }
    fn severity(&self) -> Severity { Severity::Info }
    fn description(&self) -> &'static str { "Mixed Unicode scripts in identifier or command token" }
    fn help_text(&self) -> &'static str {
        "A single word-token contains characters from multiple Unicode scripts. This may indicate \
         a homoglyph attack where Cyrillic or Greek letters substitute for Latin ones in tool names."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let mut findings = Vec::new();
        let content = &source.content;

        // Scan word tokens (sequences of non-whitespace, non-punctuation chars)
        let mut word_start: Option<usize> = None;

        let flush = |start: usize, end: usize| -> Option<Finding> {
            if end <= start { return None; }
            let word = &content[start..end];
            // Only check tokens that look like identifiers (contain letters)
            if !word.chars().any(|c| c.is_alphabetic()) { return None; }

            let scripts: std::collections::HashSet<Script> = word
                .chars()
                .filter(|c| c.is_alphabetic())
                .map(|c| c.script())
                .filter(|s| !matches!(s, Script::Common | Script::Inherited | Script::Unknown))
                .collect();

            if scripts.len() >= 2 {
                let span = source.byte_range_to_span(start, end);
                Some(
                    Finding::new(
                        "AGT006",
                        Severity::Info,
                        format!("Token '{word}' mixes {} Unicode scripts", scripts.len()),
                        span,
                        source.path.clone(),
                    )
                    .with_help(
                        "A single identifier containing characters from multiple scripts may be \
                         a homoglyph substitution attack.",
                    ),
                )
            } else {
                None
            }
        };

        for (byte_pos, ch) in content.char_indices() {
            if ch.is_alphanumeric() || ch == '_' || ch == '-' {
                if word_start.is_none() {
                    word_start = Some(byte_pos);
                }
            } else {
                if let Some(start) = word_start.take() {
                    if let Some(f) = flush(start, byte_pos) {
                        findings.push(f);
                    }
                }
            }
        }
        // Flush final word
        if let Some(start) = word_start {
            if let Some(f) = flush(start, content.len()) {
                findings.push(f);
            }
        }

        findings
    }
}
