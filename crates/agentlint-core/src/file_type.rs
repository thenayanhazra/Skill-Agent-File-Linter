use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    SkillMd,
    ClaudeMd,
    CursorRules,
    CopilotInstructions,
    McpConfig,
    GenericAgentMd,
    Unknown,
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreatAs {
    AgentInstructions,
}

impl std::str::FromStr for TreatAs {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "agent-instructions" => Ok(Self::AgentInstructions),
            other => Err(format!("unknown treat-as value: {other}")),
        }
    }
}

impl FileType {
    pub fn detect(path: &Path, treat_as: Option<TreatAs>) -> Self {
        // 1. Explicit override
        if let Some(TreatAs::AgentInstructions) = treat_as {
            if path.extension().is_some_and(|e| e == "md") {
                return Self::GenericAgentMd;
            }
        }

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        let parent = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("");

        // 2. Exact filename matches
        match file_name.as_str() {
            "skill.md" => return Self::SkillMd,
            "claude.md" | "agents.md" => return Self::ClaudeMd,
            ".cursorrules" | ".clinerules" | ".windsurfrules" => return Self::CursorRules,
            "copilot-instructions.md" if parent == ".github" => return Self::CopilotInstructions,
            _ => {}
        }

        // 3. JSON config files
        if file_name.ends_with(".json")
            && (file_name.contains("claude_desktop_config")
                || file_name.contains("mcp")
                || file_name.contains("desktop_config"))
        {
            return Self::McpConfig;
        }

        // 4. Content sniff for JSON
        if file_name.ends_with(".json") {
            return Self::Unknown;
        }

        Self::Unknown
    }

    /// Detect from path + raw file content (for content-based sniffing).
    pub fn detect_with_content(path: &Path, treat_as: Option<TreatAs>, content: &str) -> Self {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Content-sniff for SkillMd BEFORE treat_as override — a file with SKILL.md
        // frontmatter (---/triggers:/skill:) is always SkillMd regardless of treat_as.
        if file_name.ends_with(".md") {
            let sniff = &content[..content.len().min(512)];
            if sniff.starts_with("---") && (sniff.contains("skill:") || sniff.contains("triggers:")) {
                return Self::SkillMd;
            }
        }

        let ft = Self::detect(path, treat_as);
        if ft != Self::Unknown {
            return ft;
        }

        // Content-sniff JSON for mcpServers key
        if file_name.ends_with(".json") {
            let sniff = &content[..content.len().min(1024)];
            if sniff.contains("\"mcpServers\"") {
                return Self::McpConfig;
            }
        }

        Self::Unknown
    }

    pub fn is_markdown(&self) -> bool {
        matches!(self, Self::SkillMd | Self::ClaudeMd | Self::CursorRules | Self::CopilotInstructions | Self::GenericAgentMd)
    }

    pub fn is_json(&self) -> bool {
        matches!(self, Self::McpConfig)
    }
}
