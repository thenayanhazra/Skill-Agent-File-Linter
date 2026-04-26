use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    parser::json as pjson,
    rule_registry::{Rule, RuleContext},
};

// npx @scope/pkg or npx pkg — without @version tag
static NPX_UNPINNED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^@?[a-zA-Z0-9_\-/]+$").unwrap() // package without @semver
});
// uvx pkg==version — must have ==
static CURL_PIPE_SH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(curl|wget).+\|\s*(ba)?sh").unwrap()
});

static MCP_TYPES: &[FileType] = &[FileType::McpConfig];

pub struct Agt060UnpinnedSource;

impl Rule for Agt060UnpinnedSource {
    fn id(&self) -> &'static str { "AGT060" }
    fn severity(&self) -> Severity { Severity::Warn }
    fn description(&self) -> &'static str { "MCP server installed from unpinned source" }
    fn help_text(&self) -> &'static str {
        "Using npx without @version, uvx without ==version, or curl|sh pipelines for MCP \
         server installation is unsafe — the resolved package can change at any time. \
         Pin exact versions."
    }
    fn applicable_to(&self) -> &'static [FileType] { MCP_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let Some(json) = ctx.parsed.as_json() else { return vec![] };
        let mut findings = Vec::new();

        for (name, server) in pjson::mcp_servers(json) {
            let command = pjson::str_field(server, "command").unwrap_or("");
            let args = pjson::args(server);

            // Check curl|sh pattern in full args string
            let args_str = args.join(" ");
            if CURL_PIPE_SH.is_match(&args_str) || CURL_PIPE_SH.is_match(command) {
                findings.push(make_finding(
                    name,
                    Severity::Critical,
                    "curl|sh pipeline used to install MCP server — remote code execution risk",
                    ctx,
                ));
                continue;
            }

            match command {
                "npx" => {
                    // Find the package name arg (first non-flag arg)
                    let pkg = args.iter().find(|a| !a.starts_with('-'));
                    if let Some(pkg) = pkg {
                        // Check if it has a version pin: @1.2.3 or @^1.0.0
                        let has_version = pkg.contains('@') && pkg.rfind('@').is_some_and(|i| i > 0);
                        if !has_version && NPX_UNPINNED.is_match(pkg) {
                            findings.push(make_finding(
                                name,
                                Severity::Warn,
                                &format!("npx package '{pkg}' lacks version pin (e.g. {pkg}@1.0.0)"),
                                ctx,
                            ));
                        }
                    }
                }
                "uvx" => {
                    let pkg = args.iter().find(|a| !a.starts_with('-'));
                    if let Some(pkg) = pkg {
                        if !pkg.contains("==") {
                            findings.push(make_finding(
                                name,
                                Severity::Warn,
                                &format!("uvx package '{pkg}' lacks exact version pin (e.g. {pkg}==1.0.0)"),
                                ctx,
                            ));
                        }
                    }
                }
                _ => {}
            }
        }

        findings
    }
}

fn make_finding(server_name: &str, severity: Severity, msg: &str, ctx: &RuleContext<'_>) -> Finding {
    Finding::new(
        "AGT060",
        severity,
        format!("Server '{server_name}': {msg}"),
        ctx.source.byte_range_to_span(0, 1),
        ctx.source.path.clone(),
    )
    .with_help(
        "Pin exact package versions to prevent supply chain attacks via version drift.",
    )
}
