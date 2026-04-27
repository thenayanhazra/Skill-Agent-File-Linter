use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

const SENSITIVE_PATTERNS: &[&str] = &[
    "~/.ssh/",
    "~/.aws/",
    "~/.gnupg/",
    "~/.config/",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.git-credentials",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/.env",
    ".env.local",
    ".env.production",
    ".env.secret",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "credentials.json",
    "service_account.json",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "GITHUB_TOKEN",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "private_key.pem",
    "client_secret",
];

static AC: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostFirst)
        .build(SENSITIVE_PATTERNS)
        .unwrap()
});

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ProjectMemoryMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
];

#[derive(Default)]
pub struct Agt042SensitivePaths;


impl Rule for Agt042SensitivePaths {
    fn id(&self) -> &'static str { "AGT042" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn description(&self) -> &'static str { "Instructions reference sensitive filesystem paths or credentials" }
    fn help_text(&self) -> &'static str {
        "This file references credential files, SSH keys, or secret environment variables. \
         Instructions directing the agent to read these paths could exfiltrate secrets. \
         Remove these references."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        AC.find_iter(source.content.as_bytes())
            .map(|m| {
                let span = source.byte_range_to_span(m.start(), m.end());
                let snippet = &source.content[m.start()..m.end()];
                Finding::new(
                    "AGT042",
                    Severity::Critical,
                    format!("Sensitive path or credential reference: '{snippet}'"),
                    span,
                    source.path.clone(),
                )
                .with_help(self.help_text())
            })
            .collect()
    }
}
