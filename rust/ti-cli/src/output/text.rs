//! Renders a [`Document`] as aligned text: headings as styled text (no Markdown marks;
//! piped output and `--format markdown` carry those), labels in a quiet column, color on
//! the content. On a terminal every line is cut to its width.

use core::fmt::Write as _;
use std::io::{self, Write};

use super::document::{Block, Document, Line, Span, Tone};
use super::style;

/// Width of the label column.
const LABEL_WIDTH: usize = 14;
/// Indent below a heading.
const INDENT: &str = "  ";

/// Writes `doc` to `w`, cutting lines to `width` when given (a terminal).
pub fn render(doc: &Document, w: &mut impl Write, width: Option<usize>) -> io::Result<()> {
    let mut out = Lines {
        w,
        width,
        started: false,
    };
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
    width: Option<usize>,
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
        match self.width {
            Some(width) => writeln!(self.w, "{}", truncate_styled(line, width)),
            None => writeln!(self.w, "{line}"),
        }
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

/// `line` cut to `width` visible characters, ending in `…`; ANSI escape sequences do not
/// count and are kept, and a reset closes any style left open by the cut.
fn truncate_styled(line: &str, width: usize) -> String {
    if width == 0 || visible_len(line) <= width {
        return line.to_owned();
    }
    let mut out = String::with_capacity(line.len());
    let mut shown = 0;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            out.push(c);
            for c in chars.by_ref() {
                out.push(c);
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        if shown + 1 == width {
            out.push('…');
            out.push_str("\x1b[0m");
            return out;
        }
        out.push(c);
        shown += 1;
    }
    out
}

fn visible_len(line: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for c in line.chars() {
        match (in_escape, c) {
            (false, '\x1b') => in_escape = true,
            (true, c) if c.is_ascii_alphabetic() => in_escape = false,
            (true, _) => {}
            (false, _) => len += 1,
        }
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(doc: &Document, width: Option<usize>) -> String {
        let mut out = Vec::new();
        render(doc, &mut out, width).unwrap();
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
            plain(&doc, None),
            "Certificate 1 of 1\n  card.pem\n\nKey\n  algorithm      ECDSA admissible\n  \
             policies       - 1.2.3\n                 - 1.2.4\n"
        );
    }

    #[test]
    fn unlabelled_lists_have_no_label_column() {
        let mut doc = Document::default();
        doc.section("Errors")
            .items("", [Line::text("a"), Line::text("b")]);
        assert_eq!(plain(&doc, None), "Errors\n  - a\n  - b\n");
    }

    #[test]
    fn truncation_counts_only_visible_characters() {
        let styled = "\x1b[1mabcdef\x1b[0m ghij";
        assert_eq!(truncate_styled(styled, 20), styled);
        let cut = truncate_styled(styled, 5);
        assert_eq!(anstream::adapter::strip_str(&cut).to_string(), "abcd…");
        assert!(cut.ends_with("\x1b[0m"), "closes the open style");
        assert_eq!(truncate_styled("äöüßabc", 4), "äöü…\x1b[0m");
    }

    #[test]
    fn cut_to_the_terminal_width_only() {
        let mut doc = Document::default();
        doc.paragraph("x".repeat(50));
        assert!(plain(&doc, None).contains(&"x".repeat(50)));
        assert_eq!(plain(&doc, Some(10)), format!("  {}…\n", "x".repeat(7)));
    }
}
