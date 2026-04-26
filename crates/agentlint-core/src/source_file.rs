use std::path::{Path, PathBuf};

use miette::SourceSpan;
use thiserror::Error;

use crate::{
    file_type::{FileType, TreatAs},
    finding::Span,
};

#[derive(Debug, Error)]
pub enum SourceFileError {
    #[error("I/O error reading {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("File is not valid UTF-8: {path}")]
    NotUtf8 { path: PathBuf },
}

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path:         PathBuf,
    pub file_type:    FileType,
    pub content:      String,
    /// Byte offset of the start of each line (index 0 = line 1).
    pub line_offsets: Vec<usize>,
}

impl SourceFile {
    pub fn read(path: &Path, treat_as: Option<TreatAs>) -> Result<Self, SourceFileError> {
        let bytes = std::fs::read(path).map_err(|e| SourceFileError::Io { path: path.to_owned(), source: e })?;
        let content = String::from_utf8(bytes).map_err(|_| SourceFileError::NotUtf8 { path: path.to_owned() })?;
        let file_type = FileType::detect_with_content(path, treat_as, &content);
        Ok(Self::from_parts(path.to_owned(), file_type, content))
    }

    pub fn from_string(path: PathBuf, file_type: FileType, content: String) -> Self {
        Self::from_parts(path, file_type, content)
    }

    fn from_parts(path: PathBuf, file_type: FileType, content: String) -> Self {
        let mut offsets = vec![0usize];
        for (i, b) in content.bytes().enumerate() {
            if b == b'\n' {
                offsets.push(i + 1);
            }
        }
        Self { path, file_type, content, line_offsets: offsets }
    }

    /// Convert a byte range to a Span (1-based line and col).
    pub fn byte_range_to_span(&self, byte_start: usize, byte_end: usize) -> Span {
        let line = self.line_at_byte(byte_start);
        let line_offset = self.line_offsets[line - 1];
        let col_start = self.content[line_offset..byte_start].chars().count() + 1;
        let col_end = col_start + self.content[byte_start..byte_end].chars().count();
        Span { byte_start, byte_end, line, col_start, col_end }
    }

    /// Returns the 1-based line number for a byte offset.
    pub fn line_at_byte(&self, byte: usize) -> usize {
        match self.line_offsets.binary_search(&byte) {
            Ok(i) => i + 1,
            Err(i) => i,
        }
    }

    /// Returns the text of a given 1-based line (without trailing newline).
    pub fn line_text(&self, line: usize) -> &str {
        let start = self.line_offsets[line - 1];
        let end = self.line_offsets.get(line).copied().unwrap_or(self.content.len());
        self.content[start..end].trim_end_matches('\n').trim_end_matches('\r')
    }

    /// Convert a Span to a miette SourceSpan for use with miette diagnostics.
    pub fn to_source_span(&self, span: &Span) -> SourceSpan {
        (span.byte_start, span.byte_end - span.byte_start).into()
    }
}

impl miette::SourceCode for SourceFile {
    fn read_span<'a>(
        &'a self,
        span: &miette::SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<Box<dyn miette::SpanContents<'a> + 'a>, miette::MietteError> {
        self.content.read_span(span, context_lines_before, context_lines_after)
    }
}
