use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

/// A curated set of high-risk confusable pairs: (lookalike, ascii_equivalent, description).
/// These are common Latin/Cyrillic/Greek confusables used in homoglyph attacks.
const CONFUSABLES: &[(char, char, &str)] = &[
    // Cyrillic lookalikes for Latin
    ('а', 'a', "Cyrillic а (U+0430) looks like Latin a"),
    ('е', 'e', "Cyrillic е (U+0435) looks like Latin e"),
    ('о', 'o', "Cyrillic о (U+043E) looks like Latin o"),
    ('р', 'p', "Cyrillic р (U+0440) looks like Latin p"),
    ('с', 'c', "Cyrillic с (U+0441) looks like Latin c"),
    ('х', 'x', "Cyrillic х (U+0445) looks like Latin x"),
    ('ѕ', 's', "Cyrillic ѕ (U+0455) looks like Latin s"),
    ('і', 'i', "Cyrillic і (U+0456) looks like Latin i"),
    ('ј', 'j', "Cyrillic ј (U+0458) looks like Latin j"),
    // Greek lookalikes
    ('ο', 'o', "Greek ο (U+03BF) looks like Latin o"),
    ('υ', 'u', "Greek υ (U+03C5) looks like Latin u"),
    // Fullwidth
    ('ａ', 'a', "Fullwidth Latin Small Letter A (U+FF41)"),
    ('ｂ', 'b', "Fullwidth Latin Small Letter B (U+FF42)"),
    ('ｃ', 'c', "Fullwidth Latin Small Letter C (U+FF43)"),
];

// Only check inside code-like contexts: backtick spans, YAML values, command strings
static CODE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"`[^`]+`|(?m)^\s{4}.+$").unwrap());

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ProjectMemoryMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
    FileType::McpConfig,
];

pub struct Agt004Confusables;

impl Rule for Agt004Confusables {
    fn id(&self) -> &'static str { "AGT004" }
    fn severity(&self) -> Severity { Severity::Warn }
    fn description(&self) -> &'static str { "Homoglyph/confusable character in code or command context" }
    fn help_text(&self) -> &'static str {
        "Characters that visually resemble ASCII but are from different Unicode scripts can \
         cause tool name mismatches or obfuscate malicious commands. Replace with ASCII equivalents."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let mut findings = Vec::new();

        // Only check code-like spans to keep false positives low
        for m in CODE_PATTERN.find_iter(&source.content) {
            let slice = m.as_str();
            let slice_offset = m.start();
            for (byte_in_slice, ch) in slice.char_indices() {
                if let Some((_, _, desc)) = CONFUSABLES.iter().find(|(c, _, _)| *c == ch) {
                    let abs_byte = slice_offset + byte_in_slice;
                    let span = source.byte_range_to_span(abs_byte, abs_byte + ch.len_utf8());
                    findings.push(
                        Finding::new(
                            "AGT004",
                            Severity::Warn,
                            format!("Confusable character: {desc}"),
                            span,
                            source.path.clone(),
                        )
                        .with_help(self.help_text()),
                    );
                }
            }
        }

        findings
    }
}
