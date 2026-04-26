use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    parser::json as pjson,
    rule_registry::{Rule, RuleContext},
};

const SHELL_EXEC_KEYWORDS: &[&str] = &[
    "execute", "exec", "run_command", "run_code", "shell", "bash", "cmd",
    "subprocess", "system_call", "spawn", "terminal", "console", "repl",
    "eval", "evaluate", "interpreter", "script_run",
];

const NETWORK_KEYWORDS: &[&str] = &[
    "http_request", "http_get", "http_post", "fetch", "web_request",
    "curl", "wget", "network", "socket", "tcp", "udp",
    "send_data", "upload", "post_data", "webhook",
];

static MCP_TYPES: &[FileType] = &[FileType::McpConfig];

pub struct Agt063RcePair;

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

impl Rule for Agt063RcePair {
    fn id(&self) -> &'static str { "AGT063" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn description(&self) -> &'static str { "Dangerous tool combo: shell execution + network (RCE-to-C2 pair)" }
    fn help_text(&self) -> &'static str {
        "The MCP configuration grants the agent both shell execution and network capabilities. \
         This combination enables remote code execution connected to a C2: execute arbitrary \
         commands and exfiltrate results. This is extremely high-risk. Review carefully."
    }
    fn applicable_to(&self) -> &'static [FileType] { MCP_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let Some(json) = ctx.parsed.as_json() else { return vec![] };

        let servers: Vec<_> = pjson::mcp_servers(json).collect();
        let has_shell = servers.iter().any(|(_, s)| has_capability(s, SHELL_EXEC_KEYWORDS));
        let has_net = servers.iter().any(|(_, s)| has_capability(s, NETWORK_KEYWORDS));

        if has_shell && has_net {
            return vec![Finding::new(
                "AGT063",
                Severity::Critical,
                "MCP config combines shell-execution and network capabilities (RCE-to-C2 risk)",
                ctx.source.byte_range_to_span(0, 1),
                ctx.source.path.clone(),
            )
            .with_help(self.help_text())];
        }

        vec![]
    }
}
