//! Renders a [`Document`] as compact CommonMark: a title as `##`, a section as a bold
//! lead-in, fields and labelled lists as one bullet list (`- label: value`), trees as
//! nested lists, PEM as a fenced block. No tables: they cost more than they align in a
//! note or a chat. Never cut, never colored.

use std::io::{self, Write};

use super::document::{Block, Document, Line, Node, Span};

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
            Block::Title(text) => writeln!(w, "## {}", escape(text))?,
            Block::Section(text) => writeln!(w, "**{}**", escape(text))?,
            Block::Paragraph(line) => {
                // Consecutive lines stay one paragraph, with hard line breaks between.
                let mut lines = vec![inline(line)];
                while let Some(Block::Paragraph(next)) = blocks.peek() {
                    lines.push(inline(next));
                    blocks.next();
                }
                writeln!(w, "{}", lines.join("  \n"))?;
            }
            Block::Field(..) | Block::Items(..) => {
                // A run of fields and lists is one bullet list.
                let mut current = Some(block);
                while let Some(block) = current {
                    match block {
                        Block::Field(label, value) => {
                            writeln!(w, "- {}: {}", escape(label), inline(value))?;
                        }
                        Block::Items(label, items) if label.is_empty() => {
                            for item in items {
                                writeln!(w, "- {}", inline(item))?;
                            }
                        }
                        Block::Items(label, items) => {
                            writeln!(w, "- {}:", escape(label))?;
                            for item in items {
                                writeln!(w, "  - {}", inline(item))?;
                            }
                        }
                        _ => unreachable!("only fields and lists are taken"),
                    }
                    current = blocks.next_if(|b| matches!(b, Block::Field(..) | Block::Items(..)));
                }
            }
            Block::Tree(nodes) => {
                for node in nodes {
                    tree(w, node, 0)?;
                }
            }
            Block::Pem(pem) => writeln!(w, "```pem\n{}\n```", pem.trim_end())?,
        }
    }
    w.flush()
}

/// A node as a list item at `depth`, its details as hard-broken lines of the item.
fn tree(w: &mut impl Write, node: &Node, depth: usize) -> io::Result<()> {
    let indent = "  ".repeat(depth);
    write!(w, "{indent}- {}", inline(&node.line))?;
    for detail in &node.details {
        write!(w, "  \n{indent}  {}", inline(detail))?;
    }
    writeln!(w)?;
    for child in &node.children {
        tree(w, child, depth + 1)?;
    }
    Ok(())
}

fn inline(line: &Line) -> String {
    let text: String = line
        .0
        .iter()
        .map(|span| match span {
            Span::Text(t) | Span::Dim(t) => escape(t),
            Span::Code(t) => code(t),
            Span::Strong(t) | Span::Status(_, t) => format!("**{}**", escape(t.trim())),
            Span::Link(t) => format!("<{t}>"),
        })
        .collect();
    // Headings, quotes and list markers only count at the start of a line.
    if text.starts_with(['#', '>', '-', '+']) {
        format!("\\{text}")
    } else {
        text
    }
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

/// Backslash-escapes the characters that start Markdown syntax anywhere in prose.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '`' | '*' | '_' | '[' | ']' | '<') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::document::{Node, Tone};

    fn markdown(doc: &Document) -> String {
        let mut out = Vec::new();
        render(doc, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn lists_paragraphs_trees_and_pem() {
        let mut doc = Document::default();
        doc.paragraph(Line::strong("Krankenhaus Farn Schneerose"))
            .paragraph("O=202309022 NOT-VALID · C=DE")
            .field("type", Line::code("C.HCI.AUT"))
            .field(
                "status",
                Line::status(Tone::Good, "valid").and_text(", 1 year left"),
            )
            .items(
                "policies",
                [Line::code("1.2.276.0.76.4.163").and_dim(" Policy")],
            )
            .section("CAs")
            .tree(vec![Node {
                line: Line::strong("RCA"),
                details: Vec::new(),
                children: vec![Node {
                    line: Line::strong("CA"),
                    details: vec![Line::dim("policy 1.2.3")],
                    children: Vec::new(),
                }],
            }])
            .pem("-----BEGIN CERTIFICATE-----\nMII=\n-----END CERTIFICATE-----\n");
        assert_eq!(
            markdown(&doc),
            "**Krankenhaus Farn Schneerose**  \nO=202309022 NOT-VALID · C=DE\n\n\
             - type: `C.HCI.AUT`\n- status: **valid**, 1 year left\n- policies:\n  - \
             `1.2.276.0.76.4.163` Policy\n\n**CAs**\n\n- **RCA**\n  - **CA**  \n    \
             policy 1.2.3\n\n```pem\n-----BEGIN CERTIFICATE-----\nMII=\n-----END \
             CERTIFICATE-----\n```\n"
        );
    }

    #[test]
    fn unlabelled_lists_are_plain_lists() {
        let mut doc = Document::default();
        doc.section("Errors").items("", [Line::text("a")]);
        assert_eq!(markdown(&doc), "**Errors**\n\n- a\n");
    }

    #[test]
    fn markdown_syntax_in_values_is_escaped() {
        assert_eq!(escape("a*b_c|d#"), r"a\*b\_c|d#");
        assert_eq!(inline(&Line::text("# not a heading")), r"\# not a heading");
        assert_eq!(inline(&Line::text("TSL #1")), "TSL #1");
        assert_eq!(code("x`y"), "`` x`y ``");
        assert_eq!(code("1.2.3"), "`1.2.3`");
    }
}
