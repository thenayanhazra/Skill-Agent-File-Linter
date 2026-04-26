use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    rule_registry::{Rule, RuleContext},
};

static URL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"https?://[^\s\)\]"'<>]+"#).unwrap());

const URL_SHORTENERS: &[&str] = &[
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "tiny.cc", "lnkd.in", "db.tt", "qr.ae", "po.st", "bc.vc",
    "j.mp", "buzurl.com", "cutt.us", "u.bb", "yourls.org", "x.co",
    "prettylinkpro.com", "scrnch.me", "filoops.info", "vzturl.com", "qr.net",
    "1url.com", "tweez.me", "v.gd", "tr.im", "link.zip.net",
];

const PASTE_SITES: &[&str] = &[
    "pastebin.com", "paste.ee", "ghostbin.co", "hastebin.com", "pastebin.pl",
    "dpaste.org", "dpaste.com", "ideone.com", "rextester.com", "jsfiddle.net",
    "codepen.io", "repl.it", "termbin.com", "ix.io", "sprunge.us",
    "paste.opensuse.org", "gist.github.com/anonymous", "controlc.com",
    "paste2.org", "paste.ofcode.org",
];

static ALL_TYPES: &[FileType] = &[
    FileType::SkillMd,
    FileType::ClaudeMd,
    FileType::CursorRules,
    FileType::CopilotInstructions,
    FileType::GenericAgentMd,
];

#[derive(Default)]
pub struct Agt041AutoFetchUrl;


impl Rule for Agt041AutoFetchUrl {
    fn id(&self) -> &'static str { "AGT041" }
    fn severity(&self) -> Severity { Severity::Error }
    fn description(&self) -> &'static str { "Auto-fetched URL from URL shortener or paste site" }
    fn help_text(&self) -> &'static str {
        "Instructions referencing URL shorteners or paste sites may cause the agent to \
         fetch and execute remote instructions at runtime, enabling dynamic payload delivery. \
         Use direct, pinned URLs instead."
    }
    fn applicable_to(&self) -> &'static [FileType] { ALL_TYPES }

    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let source = ctx.source;
        let mut findings = Vec::new();

        for m in URL_RE.find_iter(&source.content) {
            let url = m.as_str();
            let is_shortener = URL_SHORTENERS.iter().any(|d| url.contains(d));
            let is_paste = PASTE_SITES.iter().any(|d| url.contains(d));

            if is_shortener || is_paste {
                let kind = if is_shortener { "URL shortener" } else { "paste site" };
                let span = source.byte_range_to_span(m.start(), m.end());
                findings.push(
                    Finding::new(
                        "AGT041",
                        Severity::Error,
                        format!("Reference to {kind}: {url}"),
                        span,
                        source.path.clone(),
                    )
                    .with_help(self.help_text()),
                );
            }
        }

        findings
    }
}
