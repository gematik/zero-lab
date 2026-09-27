//! What a command says, independent of how it is shown: a title, sections, fields,
//! lists and paragraphs, with inline parts that know what they are (code, emphasis,
//! links, verdicts). The text and Markdown renderers turn the same document into colored
//! aligned text for a terminal and into Markdown for pipes, notes and agents.

use jiff::tz::TimeZone;
use ti_pki::Timestamp;

/// A verdict's tone: how a status is colored or emphasized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Valid, admissible.
    Good,
    /// Phased out, warnings.
    Warn,
    /// Invalid, expired, not admissible.
    Bad,
}

/// One inline part of a line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Span {
    /// Plain prose.
    Text(String),
    /// An identifier or literal value: OIDs, types, hex, profile names.
    Code(String),
    /// What matters most in its line, e.g. a subject's common name.
    Strong(String),
    /// Secondary detail, e.g. an OID's description.
    Dim(String),
    /// A URL.
    Link(String),
    /// A verdict.
    Status(Tone, String),
}

/// A line of inline parts, built fluently: `Line::code("C.HCI.AUT").dim(" default")`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Line(pub Vec<Span>);

impl Line {
    /// Plain prose.
    pub fn text(text: impl Into<String>) -> Self {
        Line(vec![Span::Text(text.into())])
    }

    /// An identifier or literal.
    pub fn code(text: impl Into<String>) -> Self {
        Line(vec![Span::Code(text.into())])
    }

    /// Emphasis.
    pub fn strong(text: impl Into<String>) -> Self {
        Line(vec![Span::Strong(text.into())])
    }

    /// Secondary detail.
    pub fn dim(text: impl Into<String>) -> Self {
        Line(vec![Span::Dim(text.into())])
    }

    /// A URL.
    pub fn link(url: impl Into<String>) -> Self {
        Line(vec![Span::Link(url.into())])
    }

    /// A verdict.
    pub fn status(tone: Tone, text: impl Into<String>) -> Self {
        Line(vec![Span::Status(tone, text.into())])
    }

    /// Appends prose.
    #[must_use]
    pub fn and_text(mut self, text: impl Into<String>) -> Self {
        self.0.push(Span::Text(text.into()));
        self
    }

    /// Appends an identifier or literal.
    #[must_use]
    pub fn and_code(mut self, text: impl Into<String>) -> Self {
        self.0.push(Span::Code(text.into()));
        self
    }

    /// Appends emphasis.
    #[must_use]
    pub fn and_strong(mut self, text: impl Into<String>) -> Self {
        self.0.push(Span::Strong(text.into()));
        self
    }

    /// Appends secondary detail.
    #[must_use]
    pub fn and_dim(mut self, text: impl Into<String>) -> Self {
        self.0.push(Span::Dim(text.into()));
        self
    }

    /// Appends another line's parts.
    #[must_use]
    pub fn and_line(mut self, other: Line) -> Self {
        self.0.extend(other.0);
        self
    }

    /// Appends a verdict.
    #[must_use]
    pub fn and_status(mut self, tone: Tone, text: impl Into<String>) -> Self {
        self.0.push(Span::Status(tone, text.into()));
        self
    }
}

impl From<&str> for Line {
    fn from(text: &str) -> Self {
        Line::text(text)
    }
}

impl From<String> for Line {
    fn from(text: String) -> Self {
        Line::text(text)
    }
}

/// A block of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    /// `#`: the document title.
    Title(String),
    /// `##`: a section.
    Section(String),
    /// A line of prose; consecutive ones form one paragraph.
    Paragraph(Line),
    /// A labelled single value; a run of them is aligned (text) or a table (Markdown).
    Field(String, Line),
    /// A labelled list of values.
    Items(String, Vec<Line>),
    /// A hierarchy, e.g. roots and the CAs they signed.
    Tree(Vec<Node>),
    /// A PEM document: a fenced block in Markdown, left out of terminal text.
    Pem(String),
}

/// One entry of a [`Block::Tree`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Node {
    /// The entry itself.
    pub line: Line,
    /// Further lines about it, shown below it.
    pub details: Vec<Line>,
    /// Its children.
    pub children: Vec<Node>,
}

/// A command's output as blocks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Document {
    /// The blocks, in order.
    pub blocks: Vec<Block>,
}

impl Document {
    /// `# text`.
    pub fn title(&mut self, text: impl Into<String>) -> &mut Self {
        self.blocks.push(Block::Title(text.into()));
        self
    }

    /// `## text`.
    pub fn section(&mut self, text: impl Into<String>) -> &mut Self {
        self.blocks.push(Block::Section(text.into()));
        self
    }

    /// A line of prose.
    pub fn paragraph(&mut self, line: impl Into<Line>) -> &mut Self {
        self.blocks.push(Block::Paragraph(line.into()));
        self
    }

    /// `label: value`.
    pub fn field(&mut self, label: impl Into<String>, value: impl Into<Line>) -> &mut Self {
        self.blocks.push(Block::Field(label.into(), value.into()));
        self
    }

    /// A tree; nothing for no nodes.
    pub fn tree(&mut self, nodes: Vec<Node>) -> &mut Self {
        if !nodes.is_empty() {
            self.blocks.push(Block::Tree(nodes));
        }
        self
    }

    /// A PEM document.
    pub fn pem(&mut self, pem: impl Into<String>) -> &mut Self {
        self.blocks.push(Block::Pem(pem.into()));
        self
    }

    /// A labelled list; nothing for no items.
    pub fn items(
        &mut self,
        label: impl Into<String>,
        items: impl IntoIterator<Item = Line>,
    ) -> &mut Self {
        let items: Vec<Line> = items.into_iter().collect();
        if !items.is_empty() {
            self.blocks.push(Block::Items(label.into(), items));
        }
        self
    }
}

/// A span of seconds in words, the two largest adjacent units: `1 year 4 months`,
/// `3 days`, `2 hours 1 minute`, `less than a minute`.
pub fn span(seconds: u64) -> String {
    const UNITS: [(u64, &str); 5] = [
        (365 * 86_400, "year"),
        (30 * 86_400, "month"),
        (86_400, "day"),
        (3_600, "hour"),
        (60, "minute"),
    ];
    let mut parts = Vec::new();
    let mut rest = seconds;
    for (size, name) in UNITS {
        if parts.len() == 2 {
            break;
        }
        let count = rest / size;
        if count > 0 {
            parts.push(format!(
                "{count} {name}{}",
                if count == 1 { "" } else { "s" }
            ));
            rest %= size;
        } else if !parts.is_empty() {
            break;
        }
    }
    if parts.is_empty() {
        "less than a minute".to_owned()
    } else {
        parts.join(" ")
    }
}

/// `at` in the system time zone to the minute, with the zone's abbreviation (its
/// offset where it has none), e.g. `2023-02-09 00:00 CET`. Text and Markdown always
/// show local time; JSON keeps RFC 3339 UTC.
pub fn when(at: Timestamp) -> String {
    local(at, &TimeZone::system(), "%Y-%m-%d %H:%M %Z")
}

/// The local date of `at`, e.g. `2023-02-09`: for lists, where the day is what counts.
pub fn date(at: Timestamp) -> String {
    local(at, &TimeZone::system(), "%Y-%m-%d")
}

fn local(at: Timestamp, zone: &TimeZone, format: &str) -> String {
    i64::try_from(at.0)
        .ok()
        .and_then(|secs| jiff::Timestamp::from_second(secs).ok())
        .map_or_else(
            || at.to_string(),
            |ts| ts.to_zoned(zone.clone()).strftime(format).to_string(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_built_fluently() {
        let line = Line::code("C.HCI.AUT").and_dim(" default");
        assert_eq!(
            line.0,
            [Span::Code("C.HCI.AUT".into()), Span::Dim(" default".into())]
        );
    }

    #[test]
    fn empty_lists_are_left_out() {
        let mut doc = Document::default();
        doc.items("none", Vec::new()).field("a", "b");
        assert_eq!(doc.blocks, [Block::Field("a".into(), Line::text("b"))]);
    }

    #[test]
    fn spans_in_words() {
        assert_eq!(span(0), "less than a minute");
        assert_eq!(span(3 * 86_400 + 5), "3 days");
        assert_eq!(
            span(365 * 86_400 + 4 * 30 * 86_400 + 86_400),
            "1 year 4 months"
        );
        assert_eq!(span(2 * 3_600 + 60), "2 hours 1 minute");
        assert_eq!(span(365 * 86_400 + 86_400), "1 year", "stops at a gap");
    }

    #[test]
    fn timestamps_in_a_zone_with_its_abbreviation() {
        let berlin = TimeZone::get("Europe/Berlin").unwrap();
        let minutes = "%Y-%m-%d %H:%M %Z";
        // 2023-02-08T23:00:00Z, winter time, and 2023-07-01T12:00:00Z, summer time.
        assert_eq!(
            local(Timestamp(1_675_897_200), &berlin, minutes),
            "2023-02-09 00:00 CET"
        );
        assert_eq!(
            local(Timestamp(1_688_212_800), &berlin, minutes),
            "2023-07-01 14:00 CEST"
        );
        assert_eq!(
            local(Timestamp(1_675_897_200), &berlin, "%Y-%m-%d"),
            "2023-02-09",
            "the local date, not the UTC one"
        );
        assert_eq!(
            local(Timestamp(0), &TimeZone::UTC, minutes),
            "1970-01-01 00:00 UTC"
        );
    }
}
