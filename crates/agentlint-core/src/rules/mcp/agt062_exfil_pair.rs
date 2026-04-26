use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    parser::json as pjson,
    rule_registry::{Rule, RuleContext},
};

const FS_READ_KEYWORDS: &[&str] = &[
    "read_file", "readfile", "read-file", "file_read", "get_file",
    "filesystem", "file_system", "list_dir", "list_directory",
    "read_dir", "read_directory", "fs_read", "disk_read", "local_file",
];

const HTTP_KEYWORDS: &[&str] = &[
    "http_request", "http_get", "http_post", "fetch", "web_request",
    "curl", "wget", "request", "http_client", "api_call", "web_fetch",
    "make_request", "send_request", "network_request",
];

static MCP_TYPES: &[FileType] = &[FileType::McpConfig];

pub struct Agt062ExfilPair;

fn has_capability(server: &serde_json::Value, keywords: &[&str]) -> bool {
    let tools = pjson::tool_names(server);
    let description = pjson::str_field(server, "description").unwrap_or("").to_lowercase();
    let name_str = server.to_string().to_lowercase();

    keywords.iter().any(|kw| {
        tools.iter().any(|t| t.to_lowercase().contains(kw))
            || description.contains(kw)
            || name_str.contains(kw)
    })
}

impl Rule for Agt062ExfilPair {
    fn id(&self) -> &'static str { "AGT062" }
    fn severity(&self) -> Severity { Severity::Error }
    fn description(&self) -> &'static str { "Dangerous tool combo: filesystem read + arbitrary HTTP (exfil pair)" }
    fn help_text(&self) -> &'static str {
        "The MCP configuration grants the agent both filesystem read access and arbitrary HTTP \
         request capabilities on the same server. This combination enables data exfiltration: \
         read local files, send them to a remote endpoint. Review and restrict tool scopes."
    }
    fn applicable_to(&self) -> &'static [FileType] { MCP_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let Some(json) = ctx.parsed.as_json() else { return vec![] };

        // Check across ALL servers combined — exfil pair can span two servers
        let servers: Vec<_> = pjson::mcp_servers(json).collect();
        let has_fs = servers.iter().any(|(_, s)| has_capability(s, FS_READ_KEYWORDS));
        let has_http = servers.iter().any(|(_, s)| has_capability(s, HTTP_KEYWORDS));

        if has_fs && has_http {
            return vec![Finding::new(
                "AGT062",
                Severity::Error,
                "MCP config combines filesystem-read and HTTP-fetch capabilities (exfiltration risk)",
                ctx.source.byte_range_to_span(0, 1),
                ctx.source.path.clone(),
            )
            .with_help(self.help_text())];
        }

        vec![]
    }
}
