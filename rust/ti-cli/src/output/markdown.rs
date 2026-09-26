//! Renders a [`Document`] as CommonMark with GFM tables: a run of fields becomes a
//! two-column table, a labelled list becomes a bold label with a bullet list, prose
//! becomes a paragraph. Never cut, never colored.

use std::io::{self, Write};

use super::document::{Block, Document, Line, Span};

/// Writes `doc` to `w`.
pub fn render(doc: &Document, w: &mut impl Write) -> io::Result<()> {
    let mut blocks = doc.blocks.iter().peekable();
    let mut first = true;
    while let Some(block) = blocks.next() {
        if !first {
            writeln!(w)?;
        }
        first = false;
        match block {
            Block::Title(text) => writeln!(w, "# {}", escape(text))?,
            Block::Section(text) => writeln!(w, "## {}", escape(text))?,
            Block::Paragraph(line) => {
                // Consecutive lines stay one paragraph, with hard line breaks between.
                let mut lines = vec![inline(line)];
                while let Some(Block::Paragraph(next)) = blocks.peek() {
                    lines.push(inline(next));
                    blocks.next();
                }
                writeln!(w, "{}", lines.join("  \n"))?;
            }
            Block::Field(label, value) => {
                writeln!(w, "| | |\n| --- | --- |")?;
                writeln!(
                    w,
                    "| **{}** | {} |",
                    cell(&escape(label)),
                    cell(&inline(value))
                )?;
                while let Some(Block::Field(label, value)) = blocks.peek() {
                    writeln!(
                        w,
                        "| **{}** | {} |",
                        cell(&escape(label)),
                        cell(&inline(value))
                    )?;
                    blocks.next();
                }
            }
            Block::Items(label, items) => {
                if !label.is_empty() {
                    writeln!(w, "**{}**\n", escape(label))?;
                }
                for item in items {
                    writeln!(w, "- {}", inline(item))?;
                }
            }
        }
    }
    w.flush()
}

fn inline(line: &Line) -> String {
    line.0
        .iter()
        .map(|span| match span {
            Span::Text(t) | Span::Dim(t) => escape(t),
            Span::Code(t) => code(t),
            Span::Strong(t) | Span::Status(_, t) => format!("**{}**", escape(t.trim())),
            Span::Link(t) => format!("<{t}>"),
        })
        .collect()
}

/// A code span that survives backticks in `text`: the fence is one backtick longer than
/// the longest run inside.
fn code(text: &str) -> String {
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    if longest == 0 {
        format!("{fence}{text}{fence}")
    } else {
        format!("{fence} {text} {fence}")
    }
}

/// Backslash-escapes the characters that would start Markdown syntax in prose.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '#' | '|'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A table cell: pipes are escaped already by [`escape`]; code spans may still hold one.
fn cell(text: &str) -> String {
    text.replace(" | ", r" \| ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::document::Tone;

    fn markdown(doc: &Document) -> String {
        let mut out = Vec::new();
        render(doc, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn tables_lists_and_paragraphs() {
        let mut doc = Document::default();
        doc.title("Certificate 1 of 1")
            .section("Subject")
            .paragraph(Line::strong("Krankenhaus Farn Schneerose"))
            .paragraph("O=202309022 NOT-VALID · C=DE")
            .section("TI")
            .field("type", Line::code("C.HCI.AUT"))
            .field(
                "status",
                Line::status(Tone::Good, "valid").and_text(", 1 year left"),
            )
            .items(
                "policies",
                [Line::code("1.2.276.0.76.4.163").and_dim(" Policy")],
            )
            .section("Revocation")
            .field("OCSP", Line::link("http://ehca.gematik.de/ocsp/"));
        assert_eq!(
            markdown(&doc),
            "# Certificate 1 of 1\n\n## Subject\n\n**Krankenhaus Farn Schneerose**  \nO=202309022 \
             NOT-VALID · C=DE\n\n## TI\n\n| | |\n| --- | --- |\n| **type** | `C.HCI.AUT` |\n\
             | **status** | **valid**, 1 year left |\n\n**policies**\n\n- `1.2.276.0.76.4.163` \
             Policy\n\n## Revocation\n\n| | |\n| --- | --- |\n| **OCSP** | \
             <http://ehca.gematik.de/ocsp/> |\n"
        );
    }

    #[test]
    fn unlabelled_lists_are_plain_lists() {
        let mut doc = Document::default();
        doc.section("Errors").items("", [Line::text("a")]);
        assert_eq!(markdown(&doc), "## Errors\n\n- a\n");
    }

    #[test]
    fn markdown_syntax_in_values_is_escaped() {
        assert_eq!(escape("a*b_c|d#"), r"a\*b\_c\|d\#");
        assert_eq!(code("x`y"), "`` x`y ``");
        assert_eq!(code("1.2.3"), "`1.2.3`");
    }
}
