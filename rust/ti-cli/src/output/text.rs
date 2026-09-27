//! Renders a [`Document`] as aligned text: headings as styled text (no Markdown marks;
//! piped output and `--format markdown` carry those), labels in a quiet column, color on
//! the content. Long lines are left to the terminal to wrap: a verdict's detail must not
//! be cut off.

use core::fmt::Write as _;
use std::io::{self, Write};

use super::document::{Block, Document, Line, Span, Tone};
use super::style;

/// Width of the label column.
const LABEL_WIDTH: usize = 14;
/// Indent below a heading.
const INDENT: &str = "  ";

/// Writes `doc` to `w`.
pub fn render(doc: &Document, w: &mut impl Write) -> io::Result<()> {
    let mut out = Lines { w, started: false };
    for block in &doc.blocks {
        match block {
            Block::Title(text) => out.heading(1, text)?,
            Block::Section(text) => out.heading(2, text)?,
            Block::Paragraph(line) => out.line(&format!("{INDENT}{}", styled(line)))?,
            Block::Field(label, value) => {
                out.line(&format!("{INDENT}{}{}", label_column(label), styled(value)))?;
            }
            Block::Items(label, items) => {
                for (i, item) in items.iter().enumerate() {
                    // An unlabelled list under its own heading needs no label column.
                    let column = match (label.is_empty(), i) {
                        (true, _) => String::new(),
                        (false, 0) => label_column(label),
                        (false, _) => label_column(""),
                    };
                    out.line(&format!("{INDENT}{column}- {}", styled(item)))?;
                }
            }
        }
    }
    out.w.flush()
}

struct Lines<'a, W: Write> {
    w: &'a mut W,
    started: bool,
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
        self.line(&format!("{style}{text}{style:#}"))
    }

    fn line(&mut self, line: &str) -> io::Result<()> {
        self.started = true;
        writeln!(self.w, "{line}")
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
