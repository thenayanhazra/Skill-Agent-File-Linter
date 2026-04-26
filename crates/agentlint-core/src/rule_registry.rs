use crate::{
    file_type::FileType,
    finding::{Finding, Severity},
    parser::ParsedFile,
    source_file::SourceFile,
};

pub struct RuleContext<'a> {
    pub source: &'a SourceFile,
    pub parsed: &'a ParsedFile,
}

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn description(&self) -> &'static str;
    fn help_text(&self) -> &'static str;
    fn applicable_to(&self) -> &'static [FileType];
    fn check(&self, ctx: &RuleContext<'_>) -> Vec<Finding>;
    fn is_autofixable(&self) -> bool {
        false
    }
}

pub struct RuleRegistry {
    pub rules: Vec<Box<dyn Rule>>,
}

impl RuleRegistry {
    pub fn new(rules: Vec<Box<dyn Rule>>) -> Self {
        Self { rules }
    }

    pub fn all() -> Self {
        use crate::rules::{
            exfiltration::{Agt040ImageExfil, Agt041AutoFetchUrl, Agt042SensitivePaths, Agt043NetworkFileCombo},
            injection::{
                Agt020IgnoreInstructions, Agt021RoleplayJailbreak, Agt022SystemImpersonation,
                Agt023AuthorityClaim, Agt024UrgencyThreat,
            },
            mcp::{Agt060UnpinnedSource, Agt061PrivateUrl, Agt062ExfilPair, Agt063RcePair, Agt064DescriptionMismatch},
            skill::{Agt080MissingTrigger, Agt081ExternalFileRef, Agt082DisableSafety},
            unicode::{
                Agt001Bidi, Agt002ZeroWidth, Agt003TagChars, Agt004Confusables,
                Agt005Nonprintable, Agt006MixedScripts, Agt007AnsiEscape,
            },
        };

        Self::new(vec![
            // Unicode
            Box::new(Agt001Bidi),
            Box::new(Agt002ZeroWidth),
            Box::new(Agt003TagChars),
            Box::new(Agt004Confusables),
            Box::new(Agt005Nonprintable),
            Box::new(Agt006MixedScripts),
            Box::new(Agt007AnsiEscape),
            // Injection
            Box::new(Agt020IgnoreInstructions),
            Box::new(Agt021RoleplayJailbreak),
            Box::new(Agt022SystemImpersonation),
            Box::new(Agt023AuthorityClaim),
            Box::new(Agt024UrgencyThreat),
            // Exfiltration
            Box::new(Agt040ImageExfil),
            Box::new(Agt041AutoFetchUrl),
            Box::new(Agt042SensitivePaths),
            Box::new(Agt043NetworkFileCombo),
            // MCP
            Box::new(Agt060UnpinnedSource),
            Box::new(Agt061PrivateUrl),
            Box::new(Agt062ExfilPair),
            Box::new(Agt063RcePair),
            Box::new(Agt064DescriptionMismatch),
            // Skill
            Box::new(Agt080MissingTrigger),
            Box::new(Agt081ExternalFileRef),
            Box::new(Agt082DisableSafety),
        ])
    }

    pub fn filtered(&self, min_severity: Severity) -> impl Iterator<Item = &dyn Rule> {
        self.rules.iter().filter(move |r| r.severity() >= min_severity).map(|r| r.as_ref())
    }
}
