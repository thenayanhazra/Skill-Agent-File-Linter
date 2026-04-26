# agentlint

A fast static analyzer for AI agent configuration files. Detects prompt injection, hidden instructions, and dangerous tool patterns in files that LLM agents read as instructions.

```
agentlint check SKILL.md
  critical[AGT001]: Bidirectional control character U+202E RIGHT-TO-LEFT OVERRIDE at line 3, col 24
   --> SKILL.md:3:24
   help: Remove bidirectional control characters...
   fix available: run `agentlint fix`
```

## Why

Agent config files are the new macros: untrusted, executable-as-instructions, often committed to repos and pulled in transitively via dependencies, templates, and skill marketplaces. Existing linters don't see them. A poisoned `SKILL.md` in a popular skill pack is a supply-chain compromise of every agent that loads it.

## Supported File Types

| File | Detection |
|------|-----------|
| `SKILL.md` | Anthropic skills format with YAML frontmatter |
| `CLAUDE.md`, `AGENTS.md` | Project memory files |
| `.cursorrules`, `.clinerules`, `.windsurfrules` | IDE agent rules |
| `.github/copilot-instructions.md` | GitHub Copilot instructions |
| `claude_desktop_config.json` + MCP configs | MCP server lists |
| `*.md` with `--treat-as agent-instructions` | Generic instruction files |

## Detection Categories

See [RULES.md](RULES.md) for the full taxonomy.

| Range | Category | Examples |
|-------|----------|---------|
| AGT001–AGT007 | Unicode / encoding | Bidi chars, zero-width chars, tag chars, confusables |
| AGT020–AGT024 | Instruction override | "Ignore previous instructions", roleplay jailbreaks, system impersonation |
| AGT040–AGT043 | Exfiltration sinks | Image URL data exfil, URL shorteners, sensitive path reads |
| AGT060–AGT064 | Dangerous MCP tool patterns | Unpinned npx, private URLs, filesystem+HTTP combos |
| AGT080–AGT082 | Skill metadata hygiene | Missing triggers, external file refs, safety-disable instructions |

## Installation

```bash
cargo install --path crates/agentlint-cli
```

Or download a pre-built binary from [Releases](https://github.com/thenayanhazra/Skill-Agent-File-Linter/releases).

## Usage

```bash
# Scan a file
agentlint check SKILL.md

# Scan a directory (respects .gitignore)
agentlint check .

# Minimum severity filter
agentlint check . --severity error

# Output formats
agentlint check SKILL.md --format json
agentlint check SKILL.md --format sarif > results.sarif

# Read from stdin
cat SKILL.md | agentlint check --stdin --filename SKILL.md

# Auto-fix fixable findings
agentlint fix SKILL.md

# Explain a specific rule
agentlint explain AGT020

# List all rules
agentlint list-rules
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above the threshold |
| 1 | One or more findings at or above the threshold |
| 2 | Internal error |

## GitHub Action

Add to your workflow:

```yaml
- name: Scan agent configuration files
  uses: thenayanhazra/Skill-Agent-File-Linter@main
  with:
    paths: '.'
    severity: warn
    sarif-output: agentlint.sarif

- name: Upload results to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: agentlint.sarif
```

The action annotates pull requests with inline findings and uploads SARIF to GitHub code scanning.

## Rule Documentation

See [RULES.md](RULES.md) for full descriptions, examples, and false-positive guidance for each rule.

## License

MIT
