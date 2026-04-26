use std::path::PathBuf;

use agentlint_core::{
    file_type::FileType,
    parser::ParsedFile,
    rule_registry::{Rule, RuleContext},
    rules::unicode::{Agt001Bidi, Agt002ZeroWidth, Agt003TagChars, Agt005Nonprintable},
    source_file::SourceFile,
};
use proptest::prelude::*;

const BIDI_CHARS: &[char] = &[
    '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];

const ZERO_WIDTH_CHARS: &[char] = &[
    '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}',
];

/// Run a single rule directly with a Raw parsed file (avoids tree-sitter in parallel).
fn check_rule<R: Rule>(rule: &R, content: String) -> Vec<agentlint_core::finding::Finding> {
    let source = SourceFile::from_string(
        PathBuf::from("CLAUDE.md"),
        FileType::ClaudeMd,
        content,
    );
    let parsed = ParsedFile::Raw;
    let ctx = RuleContext { source: &source, parsed: &parsed };
    rule.check(&ctx)
}

proptest! {
    /// Inserting any bidi char into any ASCII text must produce an AGT001 finding.
    #[test]
    fn agt001_fires_on_any_bidi_char(
        prefix in "[a-zA-Z0-9 .,!?]{0,50}",
        suffix in "[a-zA-Z0-9 .,!?]{0,50}",
        bidi_idx in 0usize..9,
    ) {
        let bidi_char = BIDI_CHARS[bidi_idx % BIDI_CHARS.len()];
        let content = format!("{prefix}{bidi_char}{suffix}");
        let findings = check_rule(&Agt001Bidi, content);
        prop_assert!(!findings.is_empty(), "Expected AGT001 finding for U+{:04X}", bidi_char as u32);
        prop_assert!(findings.iter().all(|f| f.rule_id == "AGT001"));
    }

    /// Inserting any zero-width char must produce an AGT002 finding.
    #[test]
    fn agt002_fires_on_zero_width(
        prefix in "[a-zA-Z0-9 .,!?]{0,50}",
        suffix in "[a-zA-Z0-9 .,!?]{0,50}",
        zw_idx in 0usize..4,
    ) {
        let zw_char = ZERO_WIDTH_CHARS[zw_idx % ZERO_WIDTH_CHARS.len()];
        let content = format!("{prefix}{zw_char}{suffix}");
        let findings = check_rule(&Agt002ZeroWidth, content);
        prop_assert!(!findings.is_empty(), "Expected AGT002 finding for U+{:04X}", zw_char as u32);
    }

    /// Tag chars (U+E0000-E007F) always produce AGT003 findings.
    #[test]
    fn agt003_fires_on_tag_chars(
        prefix in "[a-zA-Z0-9 ]{0,30}",
        tag_cp in 0xE0000u32..=0xE007Fu32,
        suffix in "[a-zA-Z0-9 ]{0,30}",
    ) {
        let tag_char = char::from_u32(tag_cp).unwrap();
        let content = format!("{prefix}{tag_char}{suffix}");
        let findings = check_rule(&Agt003TagChars, content);
        prop_assert!(!findings.is_empty(), "Expected AGT003 for U+{:05X}", tag_cp);
    }

    /// Pure printable ASCII text must produce zero unicode findings.
    #[test]
    fn no_false_positives_on_ascii_agt001(content in "[\\x20-\\x7E\\n\\r\\t]{0,300}") {
        let findings = check_rule(&Agt001Bidi, content);
        prop_assert!(findings.is_empty(), "AGT001 false positive: {:?}", findings);
    }

    #[test]
    fn no_false_positives_on_ascii_agt002(content in "[\\x20-\\x7E\\n\\r\\t]{0,300}") {
        let findings = check_rule(&Agt002ZeroWidth, content);
        prop_assert!(findings.is_empty(), "AGT002 false positive: {:?}", findings);
    }

    #[test]
    fn no_false_positives_on_ascii_agt003(content in "[\\x20-\\x7E\\n\\r\\t]{0,300}") {
        let findings = check_rule(&Agt003TagChars, content);
        prop_assert!(findings.is_empty(), "AGT003 false positive: {:?}", findings);
    }

    #[test]
    fn no_false_positives_on_ascii_agt005(content in "[\\x20-\\x7E\\n\\r\\t]{0,300}") {
        let findings = check_rule(&Agt005Nonprintable, content);
        prop_assert!(findings.is_empty(), "AGT005 false positive: {:?}", findings);
    }
}
