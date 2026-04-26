/// Extract YAML frontmatter from a markdown file.
/// Returns `(yaml_text, body_byte_offset)` if frontmatter is present.
pub fn extract(content: &str) -> Option<(&str, usize)> {
    let bytes = content.as_bytes();
    if !bytes.starts_with(b"---") {
        return None;
    }
    // Find the closing ---
    let start = 3;
    // Skip the opening --- and optional newline
    let rest = &content[start..];
    // Find closing delimiter: a line that is exactly "---" (optionally with \r)
    let mut pos = 0;
    while pos < rest.len() {
        let line_start = pos;
        let line_end = memchr::memchr(b'\n', &rest.as_bytes()[pos..])
            .map(|i| pos + i + 1)
            .unwrap_or(rest.len());
        let line = rest[line_start..line_end].trim_end_matches('\n').trim_end_matches('\r');
        if line == "---" && pos > 0 {
            let yaml_text = &rest[..line_start];
            let body_offset = start + line_end;
            return Some((yaml_text, body_offset));
        }
        pos = line_end;
        if pos >= rest.len() {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_extraction() {
        let content = "---\ntitle: test\n---\nbody here";
        let (yaml, offset) = extract(content).unwrap();
        assert_eq!(yaml.trim(), "title: test");
        assert_eq!(&content[offset..], "body here");
    }

    #[test]
    fn no_frontmatter() {
        assert!(extract("# just a heading\n").is_none());
    }
}
