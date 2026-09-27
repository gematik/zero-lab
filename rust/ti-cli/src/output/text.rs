//! Renders a [`Document`] as aligned text: headings as styled text (no Markdown marks;
//! piped output and `--format markdown` carry those), labels in a quiet column, color on
//! the content. Long lines are left to the terminal to wrap: a verdict's detail must not
//! be cut off.

use core::fmt::Write as _;
use std::io::{self, Write};

use super::document::{Block, Document, Line, Node, Span, Tone};
use super::style;

/// Width of the label column.
const LABEL_WIDTH: usize = 14;
/// Indent below a heading.
const INDENT: &str = "  ";

/// Writes `doc` to `w`. Content below a heading is indented; a blank line separates
/// paragraphs, field runs, lists and trees from each other.
pub fn render(doc: &Document, w: &mut impl Write) -> io::Result<()> {
    let mut out = Lines {
        w,
        started: false,
        indent: "",
        group: None,
    };
    for block in &doc.blocks {
        match block {
            Block::Title(text) => out.heading(1, text)?,
            Block::Section(text) => out.heading(2, text)?,
            Block::Paragraph(line) => {
                out.group(Group::Paragraph)?;
                out.line(&styled(line))?;
            }
            Block::Field(label, value) => {
                out.group(Group::Fields)?;
                out.line(&format!("{}{}", label_column(label), styled(value)))?;
            }
            Block::Items(label, items) => {
                out.group(if label.is_empty() {
                    Group::List
                } else {
                    Group::Fields
                })?;
                for (i, item) in items.iter().enumerate() {
                    // An unlabelled list needs no label column.
                    let column = match (label.is_empty(), i) {
                        (true, _) => String::new(),
                        (false, 0) => label_column(label),
                        (false, _) => label_column(""),
                    };
                    out.line(&format!("{column}- {}", styled(item)))?;
                }
            }
            Block::Tree(nodes) => {
                out.group(Group::Tree)?;
                for node in nodes {
                    out.line(&styled(&node.line))?;
                    out.details(node, "")?;
                    out.children(&node.children, "")?;
                }
            }
            // A certificate's base64 helps nobody reading a terminal; Markdown and JSON
            // carry it.
            Block::Pem(_) => {}
        }
    }
    out.w.flush()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    Paragraph,
    Fields,
    List,
    Tree,
}

struct Lines<'a, W: Write> {
    w: &'a mut W,
    started: bool,
    indent: &'static str,
    group: Option<Group>,
}

impl<W: Write> Lines<'_, W> {
    fn heading(&mut self, level: usize, text: &str) -> io::Result<()> {
        if self.started {
            writeln!(self.w)?;
        }
        let style = if level == 1 {
            style::TITLE
        } else {
            style::HEADING
        };
        self.indent = "";
        self.line(&format!("{style}{text}{style:#}"))?;
        self.indent = INDENT;
        self.group = None;
        Ok(())
    }

    /// Separates a paragraph run, fields, a list and a tree by a blank line in a
    /// document without headings; under a heading, the section holds them together.
    fn group(&mut self, group: Group) -> io::Result<()> {
        if self.indent.is_empty() && self.group.is_some_and(|g| g != group) {
            writeln!(self.w)?;
        }
        self.group = Some(group);
        Ok(())
    }

    fn line(&mut self, line: &str) -> io::Result<()> {
        self.started = true;
        writeln!(self.w, "{}{line}", self.indent)
    }

    fn details(&mut self, node: &Node, prefix: &str) -> io::Result<()> {
        let bar = if node.children.is_empty() {
            "  "
        } else {
            "│ "
        };
        for detail in &node.details {
            let dim = style::DIM;
            self.line(&format!("{prefix}{dim}{bar}{dim:#}{}", styled(detail)))?;
        }
        Ok(())
    }

    fn children(&mut self, children: &[Node], prefix: &str) -> io::Result<()> {
        let dim = style::DIM;
        for (i, child) in children.iter().enumerate() {
            let last = i + 1 == children.len();
            let (branch, rest) = if last {
                ("└─ ", "   ")
            } else {
                ("├─ ", "│  ")
            };
            self.line(&format!(
                "{prefix}{dim}{branch}{dim:#}{}",
                styled(&child.line)
            ))?;
            let prefix = format!("{prefix}{dim}{rest}{dim:#}");
            self.details(child, &prefix)?;
            self.children(&child.children, &prefix)?;
        }
        Ok(())
    }
}

fn label_column(label: &str) -> String {
    let dim = style::LABEL;
    format!("{dim}{label:<LABEL_WIDTH$}{dim:#} ")
}

fn styled(line: &Line) -> String {
    let mut out = String::new();
    for span in &line.0 {
        let (style, text) = match span {
            Span::Text(t) => {
                out.push_str(t);
                continue;
            }
            Span::Code(t) => (style::ID, t),
            Span::Strong(t) => (style::EMPHASIS, t),
            Span::Dim(t) => (style::DIM, t),
            Span::Link(t) => (style::URL, t),
            Span::Status(Tone::Good, t) => (style::GOOD, t),
            Span::Status(Tone::Warn, t) => (style::WARN, t),
            Span::Status(Tone::Bad, t) => (style::BAD, t),
        };
        let _ = write!(out, "{style}{text}{style:#}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(doc: &Document) -> String {
        let mut out = Vec::new();
        render(doc, &mut out).unwrap();
        anstream::adapter::strip_str(core::str::from_utf8(&out).unwrap()).to_string()
    }

    #[test]
    fn layout() {
        let mut doc = Document::default();
        doc.title("Certificate 1 of 1")
            .paragraph(Line::code("card.pem"))
            .section("Key")
            .field(
                "algorithm",
                Line::text("ECDSA ").and_status(Tone::Good, "admissible"),
            )
            .items("policies", [Line::code("1.2.3"), Line::code("1.2.4")]);
        assert_eq!(
            plain(&doc),
            "Certificate 1 of 1\n  card.pem\n\nKey\n  algorithm      ECDSA admissible\n  \
             policies       - 1.2.3\n                 - 1.2.4\n"
        );
    }

    #[test]
    fn unlabelled_lists_have_no_label_column() {
        let mut doc = Document::default();
        doc.section("Errors")
            .items("", [Line::text("a"), Line::text("b")]);
        assert_eq!(plain(&doc), "Errors\n  - a\n  - b\n");
    }
}
