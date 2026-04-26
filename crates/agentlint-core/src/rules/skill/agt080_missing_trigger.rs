use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    parser::frontmatter,
    rule_registry::{Rule, RuleContext},
};

// Common English stopwords to exclude from trigger keyword check
const STOPWORDS: &[&str] = &[
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "as", "is", "was", "are", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "can", "it", "its", "this", "that",
    "these", "those", "i", "you", "he", "she", "we", "they", "my", "your",
    "his", "her", "our", "their", "which", "who", "what", "when", "where",
    "how", "why", "not", "no", "so", "if", "then", "than", "also", "just",
    "use", "help", "make", "create", "get", "set", "run", "add", "new", "all",
];

static SKILL_TYPES: &[FileType] = &[FileType::SkillMd];

pub struct Agt080MissingTrigger;

impl Rule for Agt080MissingTrigger {
    fn id(&self) -> &'static str { "AGT080" }
    fn severity(&self) -> Severity { Severity::Info }
    fn description(&self) -> &'static str { "SKILL.md frontmatter missing meaningful trigger keywords in description" }
    fn help_text(&self) -> &'static str {
        "The skill's frontmatter 'description' field should contain at least 2 non-generic \
         content words so the agent can reliably match user intent to this skill."
    }
    fn applicable_to(&self) -> &'static [FileType] { SKILL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let Some((yaml_text, _)) = frontmatter::extract(&source.content) else {
            return vec![Finding::new(
                "AGT080",
                Severity::Info,
                "SKILL.md has no YAML frontmatter",
                source.byte_range_to_span(0, 0.min(source.content.len())),
                source.path.clone(),
            )
            .with_help(self.help_text())];
        };

        // Simple YAML key extraction: find "description:" line
        let description = yaml_text
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("description:")
                    .map(|rest| rest.trim().trim_matches('"').trim_matches('\'').to_owned())
            });

        let description = match description {
            Some(d) if !d.is_empty() => d,
            _ => {
                return vec![Finding::new(
                    "AGT080",
                    Severity::Info,
                    "SKILL.md frontmatter 'description' field is missing or empty",
                    source.byte_range_to_span(0, 3.min(source.content.len())),
                    source.path.clone(),
                )
                .with_help(self.help_text())];
            }
        };

        // Count non-stopword content words
        let content_words: Vec<_> = description
            .split_whitespace()
            .filter(|w| {
                let lower = w.to_lowercase();
                let clean: String = lower.chars().filter(|c| c.is_alphabetic()).collect();
                !clean.is_empty() && !STOPWORDS.contains(&clean.as_str())
            })
            .collect();

        if content_words.len() < 2 {
            return vec![Finding::new(
                "AGT080",
                Severity::Info,
                format!(
                    "SKILL.md description '{description}' has too few content words ({} found, need ≥2)",
                    content_words.len()
                ),
                source.byte_range_to_span(0, 3.min(source.content.len())),
                source.path.clone(),
            )
            .with_help(self.help_text())];
        }

        vec![]
    }
}
