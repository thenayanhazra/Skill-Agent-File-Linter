pub mod frontmatter;
pub mod json;
pub mod markdown;

use crate::{file_type::FileType, source_file::SourceFile};

/// The pre-parsed representation of a file, shared across all rules.
pub enum ParsedFile {
    Markdown(markdown::ParsedMarkdown),
    Json(serde_json::Value),
    Raw,
}

impl ParsedFile {
    pub fn parse(source: &SourceFile) -> Self {
        match &source.file_type {
            FileType::McpConfig => {
                match serde_json::from_str(&source.content) {
                    Ok(v) => Self::Json(v),
                    Err(_) => Self::Raw,
                }
            }
            ft if ft.is_markdown() => Self::Markdown(markdown::ParsedMarkdown::parse(&source.content)),
            _ => Self::Raw,
        }
    }

    pub fn as_markdown(&self) -> Option<&markdown::ParsedMarkdown> {
        if let Self::Markdown(m) = self { Some(m) } else { None }
    }

    pub fn as_json(&self) -> Option<&serde_json::Value> {
        if let Self::Json(v) = self { Some(v) } else { None }
    }
}
