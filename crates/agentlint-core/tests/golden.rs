use std::path::{Path, PathBuf};

use agentlint_core::{
    engine::{scan_file, ScanOptions},
    file_type::TreatAs,
    finding::Severity,
    rule_registry::RuleRegistry,
    source_file::SourceFile,
};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("corpus")
}

fn scan_corpus_file(path: &Path) -> Vec<agentlint_core::finding::Finding> {
    // Treat any .md corpus file as agent instructions so rules apply even to
    // files with non-canonical names like bidi_positive.md.
    let treat_as = path.extension()
        .and_then(|e| e.to_str())
        .filter(|&e| e == "md")
        .map(|_| TreatAs::AgentInstructions);
    let source = SourceFile::read(path, treat_as).expect("failed to read corpus file");
    let registry = RuleRegistry::all();
    let opts = ScanOptions { min_severity: Severity::Info };
    scan_file(&source, &registry, &opts)
}

/// Verify that known positive fixtures produce at least one finding of the expected rule.
macro_rules! positive_test {
    ($name:ident, $file:expr, $rule_id:expr) => {
        #[test]
        fn $name() {
            let corpus = corpus_dir();
            let path = corpus.join($file);
            assert!(path.exists(), "Corpus fixture not found: {}", path.display());
            let findings = scan_corpus_file(&path);
            let matched: Vec<_> = findings.iter().filter(|f| f.rule_id == $rule_id).collect();
            assert!(
                !matched.is_empty(),
                "Expected {} finding in {}, got findings: {:?}",
                $rule_id,
                $file,
                findings.iter().map(|f| f.rule_id).collect::<Vec<_>>()
            );
        }
    };
}

/// Verify that known negative fixtures produce zero findings for the given rule.
macro_rules! negative_test {
    ($name:ident, $file:expr, $rule_id:expr) => {
        #[test]
        fn $name() {
            let corpus = corpus_dir();
            let path = corpus.join($file);
            assert!(path.exists(), "Corpus fixture not found: {}", path.display());
            let findings = scan_corpus_file(&path);
            let matched: Vec<_> = findings.iter().filter(|f| f.rule_id == $rule_id).collect();
            assert!(
                matched.is_empty(),
                "Unexpected {} finding in {}: {:?}",
                $rule_id,
                $file,
                matched
            );
        }
    };
}

// AGT001 — Bidi chars
positive_test!(agt001_positive, "AGT001/bidi_positive.md", "AGT001");
negative_test!(agt001_negative, "AGT001/bidi_negative.md", "AGT001");

// AGT002 — Zero-width chars
positive_test!(agt002_positive, "AGT002/zwsp_positive.md", "AGT002");
negative_test!(agt002_negative, "AGT002/zwsp_negative.md", "AGT002");

// AGT003 — Tag chars
positive_test!(agt003_positive, "AGT003/tag_positive.md", "AGT003");
negative_test!(agt003_negative, "AGT003/tag_negative.md", "AGT003");

// AGT005 — Non-printable
positive_test!(agt005_positive, "AGT005/nonprintable_positive.md", "AGT005");
negative_test!(agt005_negative, "AGT005/nonprintable_negative.md", "AGT005");

// AGT007 — ANSI escapes
positive_test!(agt007_positive, "AGT007/ansi_positive.md", "AGT007");
negative_test!(agt007_negative, "AGT007/ansi_negative.md", "AGT007");

// AGT020 — Instruction override
positive_test!(agt020_positive, "AGT020/override_positive.md", "AGT020");
negative_test!(agt020_negative, "AGT020/override_negative.md", "AGT020");

// AGT021 — Roleplay jailbreak
positive_test!(agt021_positive, "AGT021/jailbreak_positive.md", "AGT021");
negative_test!(agt021_negative, "AGT021/jailbreak_negative.md", "AGT021");

// AGT040 — Image exfil
positive_test!(agt040_positive, "AGT040/image_exfil_positive.md", "AGT040");
negative_test!(agt040_negative, "AGT040/image_exfil_negative.md", "AGT040");

// AGT042 — Sensitive paths
positive_test!(agt042_positive, "AGT042/sensitive_paths_positive.md", "AGT042");
negative_test!(agt042_negative, "AGT042/sensitive_paths_negative.md", "AGT042");

// AGT060 — Unpinned source (curl|sh is critical, but unpinned npx is warn+)
positive_test!(agt060_positive, "AGT060/unpinned_positive.json", "AGT060");
negative_test!(agt060_negative, "AGT060/pinned_negative.json", "AGT060");

// AGT080 — Missing trigger
positive_test!(agt080_positive, "AGT080/missing_trigger_positive.md", "AGT080");
negative_test!(agt080_negative, "AGT080/good_trigger_negative.md", "AGT080");

/// Clean skill should produce ZERO findings.
#[test]
fn clean_skill_zero_findings() {
    let corpus = corpus_dir();
    let path = corpus.join("clean_skill.md");
    assert!(path.exists(), "Clean skill fixture not found");
    let findings = scan_corpus_file(&path);
    assert!(
        findings.is_empty(),
        "Expected zero findings on clean_skill.md, got: {:?}",
        findings.iter().map(|f| (f.rule_id, f.message.as_str())).collect::<Vec<_>>()
    );
}
