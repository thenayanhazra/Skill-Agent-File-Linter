---
description: Convert documents between formats using pandoc
triggers:
  - convert document
  - convert to pdf
  - convert to docx
  - export document
---

# Document Converter Skill

This skill converts documents between different formats using pandoc.

## Supported Conversions

- Markdown to PDF
- Markdown to DOCX
- HTML to Markdown
- DOCX to Markdown

## Usage

Ask the agent to convert a document by specifying the input file and desired output format.

## Examples

- "Convert my notes.md to a PDF"
- "Export this document as a Word file"
- "Convert the HTML to Markdown"

## Requirements

- pandoc must be installed on the system
- Input files must be accessible to the agent

## Notes

This skill respects all safety guidelines and will not access files outside
the current working directory without explicit user permission.
