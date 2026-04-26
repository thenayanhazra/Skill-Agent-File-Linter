use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    parser::json as pjson,
    rule_registry::{Rule, RuleContext},
};

// RFC-1918 private IP ranges + localhost
static PRIVATE_IP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        https?://(?:
            localhost |
            127\.\d+\.\d+\.\d+ |
            10\.\d+\.\d+\.\d+ |
            172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+ |
            192\.168\.\d+\.\d+ |
            \[::1\]
        )",
    )
    .unwrap()
});

static MCP_TYPES: &[FileType] = &[FileType::McpConfig];

#[derive(Default)]
pub struct Agt061PrivateUrl;


impl Rule for Agt061PrivateUrl {
    fn id(&self) -> &'static str { "AGT061" }
    fn severity(&self) -> Severity { Severity::Error }
    fn description(&self) -> &'static str { "MCP server points to private/local URL" }
    fn help_text(&self) -> &'static str {
        "A server URL pointing to localhost or an RFC-1918 private IP in a shared config file \
         will not work for other users and may indicate a credential-theft attack targeting \
         local services. Use public URLs or document the local-only intent."
    }
    fn applicable_to(&self) -> &'static [FileType] { MCP_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let Some(json) = ctx.parsed.as_json() else { return vec![] };
        let mut findings = Vec::new();

        // Check the whole JSON text for private URLs
        let json_text = serde_json::to_string(json).unwrap_or_default();

        for (name, server) in pjson::mcp_servers(json) {
            // Check url field
            if let Some(url) = pjson::str_field(server, "url") {
                if PRIVATE_IP.is_match(url) {
                    findings.push(Finding::new(
                        "AGT061",
                        Severity::Error,
                        format!("Server '{name}' URL '{url}' is a private/local address"),
                        ctx.source.byte_range_to_span(0, 1),
                        ctx.source.path.clone(),
                    ).with_help(self.help_text()));
                }
            }
            // Check args for URL-like values
            for arg in pjson::args(server) {
                if PRIVATE_IP.is_match(arg) {
                    findings.push(Finding::new(
                        "AGT061",
                        Severity::Error,
                        format!("Server '{name}' arg '{arg}' is a private/local address"),
                        ctx.source.byte_range_to_span(0, 1),
                        ctx.source.path.clone(),
                    ).with_help(self.help_text()));
                }
            }
        }
        drop(json_text);

        findings
    }
}
