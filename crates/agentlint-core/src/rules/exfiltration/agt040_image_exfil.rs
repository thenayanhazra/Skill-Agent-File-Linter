use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

// Match markdown images: ![alt](url)
static IMG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"!\[[^\]]*\]\(([^)]+)\)").unwrap());

// Query parameters that commonly carry exfiltrated data
const DATA_PARAMS: &[&str] = &[
    "data=", "text=", "content=", "msg=", "message=", "q=", "query=",
    "input=", "payload=", "token=", "secret=", "key=", "value=",
    "body=", "output=", "result=", "info=", "context=",
];

// Domains that are local/safe (not exfil sinks)
const LOCAL_DOMAINS: &[&str] = &["localhost", "127.0.0.1", "0.0.0.0", "::1"];

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ClaudeMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
];

#[derive(Default)]
pub struct Agt040ImageExfil;


impl Rule for Agt040ImageExfil {
    fn id(&self) -> &'static str { "AGT040" }
    fn severity(&self) -> Severity { Severity::Error }
    fn description(&self) -> &'static str { "Markdown image with remote URL and data-carrying query string" }
    fn help_text(&self) -> &'static str {
        "A markdown image URL contains query parameters that could carry exfiltrated data. \
         When rendered by an agent, this causes the agent to make an HTTP request with potentially \
         sensitive data embedded in the URL. Remove or sanitize the image URL."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let mut findings = Vec::new();

        for cap in IMG_RE.captures_iter(&source.content) {
            let url = cap.get(1).map_or("", |m| m.as_str()).trim();
            let full_match = cap.get(0).unwrap();

            // Only care about remote HTTP URLs
            if !url.starts_with("http://") && !url.starts_with("https://") {
                continue;
            }

            // Skip local domains
            let is_local = LOCAL_DOMAINS.iter().any(|d| url.contains(d));
            if is_local { continue; }

            // Check for data-carrying query params
            if let Some(query_start) = url.find('?') {
                let query = &url[query_start + 1..];
                let has_data_param = DATA_PARAMS.iter().any(|p| query.contains(p));
                if has_data_param {
                    let span = source.byte_range_to_span(full_match.start(), full_match.end());
                    findings.push(
                        Finding::new(
                            "AGT040",
                            Severity::Error,
                            format!("Image URL with data-carrying query string: {url}"),
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
