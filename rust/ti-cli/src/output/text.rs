//! Renders a [`Document`] as aligned text: headings as styled text (no Markdown marks;
//! piped output and `--format markdown` carry those), labels in a quiet column, color on
//! the content. Long lines are left to the terminal to wrap: a verdict's detail must not
//! be cut off.

use core::fmt::Write as _;
use std::io::{self, Write};

use super::document::{Block, Document, Line, Span, Tone, TreeRow};
use super::style;

/// Width of the label column.
const LABEL_WIDTH: usize = 14;
/// Indent below a heading.
const INDENT: &str = "  ";

/// Writes `doc` to `w`. Content below a heading is indented; a blank line separates
/// paragraphs, field runs, lists and tables from each other.
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
                    // A labelled list is a field with several values, one per line under
                    // the value column; an unlabelled one is a list of statements.
                    let column = match (label.is_empty(), i) {
                        (true, _) => "- ".to_owned(),
                        (false, 0) => label_column(label),
                        (false, _) => label_column(""),
                    };
                    out.line(&format!("{column}{}", styled(item)))?;
                }
            }
            Block::Table(headings, rows) => {
                out.group(Group::Table)?;
                let mut widths: Vec<usize> = headings.iter().map(|h| h.chars().count()).collect();
                for row in rows {
                    for (width, cell) in widths.iter_mut().zip(row) {
                        *width = (*width).max(cell.plain().chars().count());
                    }
                }
                let label = style::LABEL;
                let heading = headings
                    .iter()
                    .map(|h| (format!("{label}{h}{label:#}"), h.chars().count()));
                out.line(&table_row(heading, &widths))?;
                for row in rows {
                    let cells = row.iter().map(|c| (styled(c), c.plain().chars().count()));
                    out.line(&table_row(cells, &widths))?;
                }
            }
            Block::Tree(trees) => {
                out.group(Group::Table)?;
                let rows: Vec<(&TreeRow, String)> = trees
                    .iter()
                    .flat_map(|rows| rows.iter().zip(super::document::tree_prefixes(rows.len())))
                    .collect();
                let width = rows
                    .iter()
                    .map(|(row, prefix)| prefix.chars().count() + row.name.plain().chars().count())
                    .max()
                    .unwrap_or(0);
                for (row, prefix) in rows {
                    let used = prefix.chars().count() + row.name.plain().chars().count();
                    let label = style::LABEL;
                    let mut line = format!("{label}{prefix}{label:#}{}", styled(&row.name));
                    if !row.detail.0.is_empty() {
                        let _ = write!(
                            line,
                            "{:pad$}{}",
                            "",
                            styled(&row.detail),
                            pad = width - used + 3
                        );
                    }
                    out.line(&line)?;
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
    Table,
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

    /// Separates a paragraph run, fields, a list and a table by a blank line in a
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
}

/// Styled cells padded to `widths` by their visible length, two spaces apart; nothing
/// after the last non-empty cell.
fn table_row(cells: impl Iterator<Item = (String, usize)>, widths: &[usize]) -> String {
    let cells: Vec<(String, usize)> = cells.collect();
    let last = cells.iter().rposition(|(_, len)| *len > 0).unwrap_or(0);
    let mut line = String::new();
    for (i, (cell, len)) in cells.iter().enumerate().take(last + 1) {
        line.push_str(cell);
        if i < last {
            let _ = write!(line, "{:pad$}", "", pad = widths[i] - len + 2);
        }
    }
    line
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
    fn tables_align_columns_by_visible_width() {
        let mut doc = Document::default();
        doc.table(
            &["TYPE", "HOLDER", "ID"],
            vec![
                vec![
                    Line::strong("SMC-B"),
                    Line::text("Praxis Müller"),
                    Line::code("1"),
                ],
                vec![Line::strong("HBA"), Line::text("Dr. A"), Line::code("22")],
            ],
        );
        assert_eq!(
            plain(&doc),
            "TYPE   HOLDER         ID\nSMC-B  Praxis Müller  1\nHBA    Dr. A          22\n"
        );
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
             policies       1.2.3\n                 1.2.4\n"
        );
    }

    #[test]
    fn trees_draw_branches_and_align_details() {
        let row = |name: &str, detail: &str| TreeRow {
            name: Line::strong(name),
            detail: Line::dim(detail),
        };
        let mut doc = Document::default();
        doc.section("Trust").tree(vec![
            row("Praxis", "end entity"),
            row("SMCB-CA51", "CA"),
            row("RCA5", "root"),
        ]);
        assert_eq!(
            plain(&doc),
            "Trust\n  Praxis          end entity\n  └── SMCB-CA51   CA\n      └── RCA5    root\n"
        );
        // A second tree right after joins the block: one column for both.
        doc.tree(vec![row("TSL #1", "list"), row("Signer", "TSL signer")]);
        assert_eq!(
            plain(&doc),
            "Trust\n  Praxis          end entity\n  └── SMCB-CA51   CA\n      └── RCA5    root\n  \
             TSL #1          list\n  └── Signer      TSL signer\n"
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
