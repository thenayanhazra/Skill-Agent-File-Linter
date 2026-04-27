use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

const FILE_READ_PATTERNS: &[&str] = &[
    "cat ", "read ", "open(", "open (", "with open", "file.read",
    "readfile", "read_file", "fs.readFile", "fs.readFileSync",
    "get-content", "get_content", "slurp", "io.read",
];

const NETWORK_PATTERNS: &[&str] = &[
    "curl ", "wget ", "fetch(", "requests.get", "requests.post",
    "http.get", "http.post", "urllib", "httpx", "nc ", "ncat ",
    "netcat", "send(", "socket.send", "POST ", "GET http",
];

static FILE_AC: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(FILE_READ_PATTERNS)
        .unwrap()
});

static NET_AC: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(NETWORK_PATTERNS)
        .unwrap()
});

const WINDOW: usize = 500;

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ProjectMemoryMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
];

#[derive(Default)]
pub struct Agt043NetworkFileCombo;


impl Rule for Agt043NetworkFileCombo {
    fn id(&self) -> &'static str { "AGT043" }
    fn severity(&self) -> Severity { Severity::Error }
    fn description(&self) -> &'static str { "Instructions combine local file read with network call (potential exfil)" }
    fn help_text(&self) -> &'static str {
        "Instructions that both read local files and make network calls in close proximity \
         may be attempting to exfiltrate file contents. Review carefully."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let content = source.content.as_bytes();
        let mut findings = Vec::new();

        // For each file-read mention, look for a network command within WINDOW chars
        for file_m in FILE_AC.find_iter(content) {
            let window_start = file_m.start().saturating_sub(WINDOW);
            let window_end = (file_m.end() + WINDOW).min(content.len());
            let window = &content[window_start..window_end];

            if NET_AC.find(window).is_some() {
                let span = source.byte_range_to_span(file_m.start(), file_m.end());
                let snippet = &source.content[file_m.start()..file_m.end()];
                findings.push(
                    Finding::new(
                        "AGT043",
                        Severity::Error,
                        format!("File-read command '{snippet}' near network call within {WINDOW} chars"),
                        span,
                        source.path.clone(),
                    )
                    .with_help(self.help_text()),
                );
                break; // One finding per file is enough to avoid noise
            }
        }

        findings
    }
}
