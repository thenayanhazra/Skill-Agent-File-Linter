use once_cell::sync::Lazy;
use tree_sitter::Parser;

static LANGUAGE: Lazy<tree_sitter::Language> = Lazy::new(|| tree_sitter_md::LANGUAGE.into());

pub struct ParsedMarkdown {
    pub images: Vec<ImageNode>,
    pub links:  Vec<LinkNode>,
}

#[derive(Debug, Clone)]
pub struct ImageNode {
    pub alt:        String,
    pub url:        String,
    pub byte_start: usize,
    pub byte_end:   usize,
}

#[derive(Debug, Clone)]
pub struct LinkNode {
    pub text:       String,
    pub url:        String,
    pub byte_start: usize,
    pub byte_end:   usize,
}

impl ParsedMarkdown {
    pub fn parse(content: &str) -> Self {
        let mut parser = Parser::new();
        if parser.set_language(&LANGUAGE).is_err() {
            return Self { images: vec![], links: vec![] };
        }
        let tree = parser.parse(content, None);

        let mut images = Vec::new();
        let mut links = Vec::new();

        if let Some(tree) = tree {
            let root = tree.root_node();
            collect_nodes(root, content, &mut images, &mut links);
        }

        Self { images, links }
    }
}

fn collect_nodes(
    node: tree_sitter::Node<'_>,
    source: &str,
    images: &mut Vec<ImageNode>,
    links: &mut Vec<LinkNode>,
) {
    let kind = node.kind();

    if kind == "image" {
        let url = child_text(node, source, "image_destination")
            .or_else(|| child_text(node, source, "link_destination"))
            .unwrap_or_default();
        let alt = child_text(node, source, "image_description")
            .or_else(|| child_text(node, source, "link_text"))
            .unwrap_or_default();
        images.push(ImageNode {
            alt,
            url,
            byte_start: node.start_byte(),
            byte_end: node.end_byte(),
        });
    } else if kind == "link" || kind == "inline_link" {
        let url = child_text(node, source, "link_destination").unwrap_or_default();
        let text = child_text(node, source, "link_text").unwrap_or_default();
        links.push(LinkNode {
            text,
            url,
            byte_start: node.start_byte(),
            byte_end: node.end_byte(),
        });
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_nodes(child, source, images, links);
    }
}

fn child_text(node: tree_sitter::Node<'_>, source: &str, kind: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == kind {
            return Some(child.utf8_text(source.as_bytes()).unwrap_or("").to_owned());
        }
    }
    None
}
