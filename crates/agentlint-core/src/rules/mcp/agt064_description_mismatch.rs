use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    parser::json as pjson,
    rule_registry::{Rule, RuleContext},
};

/// Capability claims that must be backed by tool definitions.
const CAPABILITY_CLAIMS: &[(&str, &str)] = &[
    ("execute code", "code execution"),
    ("run code", "code execution"),
    ("shell access", "shell"),
    ("full filesystem", "filesystem"),
    ("file system access", "filesystem"),
    ("read any file", "file read"),
    ("write any file", "file write"),
    ("send emails", "email"),
    ("access your calendar", "calendar"),
    ("access database", "database"),
    ("full internet access", "http"),
    ("unrestricted access", "unrestricted"),
    ("admin access", "admin"),
    ("root access", "root"),
];

static MCP_TYPES: &[FileType] = &[FileType::McpConfig];

#[derive(Default)]
pub struct Agt064DescriptionMismatch;


impl Rule for Agt064DescriptionMismatch {
    fn id(&self) -> &'static str { "AGT064" }
    fn severity(&self) -> Severity { Severity::Warn }
    fn description(&self) -> &'static str { "Server description claims capabilities not reflected in tool list" }
    fn help_text(&self) -> &'static str {
        "The server's description field claims capabilities that do not appear in its tool \
         definitions. This mismatch may indicate an attempt to mislead agents into granting \
         unnecessary permissions."
    }
    fn applicable_to(&self) -> &'static [FileType] { MCP_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let Some(json) = ctx.parsed.as_json() else { return vec![] };
        let mut findings = Vec::new();

        for (name, server) in pjson::mcp_servers(json) {
            let description = match pjson::str_field(server, "description") {
                Some(d) => d.to_lowercase(),
                None => continue,
            };

            let tools = pjson::tool_names(server);
            let tools_lower: Vec<_> = tools.iter().map(|t| t.to_lowercase()).collect();
            let tools_text = tools_lower.join(" ");

            for (claim, capability) in CAPABILITY_CLAIMS {
                if description.contains(claim) && !tools_text.contains(capability) {
                    findings.push(Finding::new(
                        "AGT064",
                        Severity::Warn,
                        format!(
                            "Server '{name}' description claims '{claim}' but no matching tool found for '{capability}'"
                        ),
                        ctx.source.byte_range_to_span(0, 1),
                        ctx.source.path.clone(),
                    ).with_help(self.help_text()));
                }
            }
        }

        findings
    }
}
