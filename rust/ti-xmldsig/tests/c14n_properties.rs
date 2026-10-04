//! TSLSIG-016 properties of Exclusive C14N over generated, namespace-rich documents: the
//! canonical form is a fixed point, and it does not depend on how the same document is
//! written (attribute order, quotes, empty-element syntax, redundant namespace
//! declarations, character references).

use std::fmt::Write as _;

use proptest::prelude::*;
use ti_xmldsig::{Document, Limits};

/// Prefixes and the namespaces each may be bound to; distinct per prefix, so two
/// attributes with different prefixes never share an expanded name.
const PREFIXES: [(&str, [&str; 2]); 3] = [
    ("a", ["urn:a1", "urn:a2"]),
    ("b", ["urn:b1", "urn:b2"]),
    ("c", ["urn:c1", "urn:c2"]),
];
const DEFAULTS: [&str; 3] = ["", "urn:d1", "urn:d2"];
const LOCALS: [&str; 3] = ["x", "y", "z"];

#[derive(Debug, Clone)]
enum Content {
    Text(String),
    Element(Element),
}

#[derive(Debug, Clone)]
struct Element {
    prefix: Option<usize>,
    local: usize,
    /// (prefix, local) pairs, at most one per pair.
    attributes: Vec<(Option<usize>, usize, String)>,
    /// Namespace (re)declarations: prefix index → which of its two namespaces.
    declarations: Vec<(usize, usize)>,
    /// The default namespace, if declared here.
    default: Option<usize>,
    children: Vec<Content>,
}

/// How the same document is written.
// Independent toggles, each varied on its own by the strategy.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy)]
struct Style {
    reverse_attributes: bool,
    single_quotes: bool,
    self_close_empty: bool,
    redundant_declarations: bool,
    escape_gt: bool,
    char_refs: bool,
}

fn text() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            Just('a'),
            Just(' '),
            Just('&'),
            Just('<'),
            Just('>'),
            Just('"'),
            Just('\''),
            Just('\t'),
            Just('\n'),
            Just('\r'),
            Just('é'),
            Just('€'),
            Just('𝄞'),
        ],
        0..6,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

fn element() -> impl Strategy<Value = Element> {
    let leaf = (
        proptest::option::of(0..3usize),
        0..3usize,
        proptest::collection::btree_map((proptest::option::of(0..3usize), 0..3usize), text(), 0..4),
        proptest::collection::btree_map(0..3usize, 0..2usize, 0..3),
        proptest::option::of(0..3usize),
    )
        .prop_map(
            |(prefix, local, attributes, declarations, default)| Element {
                prefix,
                local,
                attributes: attributes
                    .into_iter()
                    .map(|((p, l), v)| (p, l, v))
                    .collect(),
                declarations: declarations.into_iter().collect(),
                default,
                children: Vec::new(),
            },
        );
    leaf.prop_recursive(4, 24, 4, |inner| {
        (
            inner.clone(),
            proptest::collection::vec(
                prop_oneof![
                    text().prop_map(Content::Text),
                    inner.prop_map(Content::Element)
                ],
                0..4,
            ),
        )
            .prop_map(|(mut e, children)| {
                e.children = children;
                e
            })
    })
}

fn style() -> impl Strategy<Value = Style> {
    any::<[bool; 6]>().prop_map(|b| Style {
        reverse_attributes: b[0],
        single_quotes: b[1],
        self_close_empty: b[2],
        redundant_declarations: b[3],
        escape_gt: b[4],
        char_refs: b[5],
    })
}

fn escape(value: &str, style: Style, quote: char, out: &mut String) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' if style.escape_gt => out.push_str("&gt;"),
            // Raw carriage returns and, in attributes, tabs and line feeds would be
            // normalized away by the parser; a reference keeps the character.
            '\r' => out.push_str("&#13;"),
            '\t' | '\n' if quote != '\0' => {
                let _ = write!(out, "&#{};", u32::from(c));
            }
            c if c == quote => {
                let _ = write!(out, "&#{};", u32::from(c));
            }
            c if style.char_refs && !c.is_ascii() => {
                let _ = write!(out, "&#x{:X};", u32::from(c));
            }
            c => out.push(c),
        }
    }
}

/// Writes `e`; `scope` holds, per prefix, which of its namespaces is in scope (every
/// prefix is bound at the root, so any use below is well-formed).
fn write_element(e: &Element, style: Style, scope: [usize; 3], root: bool, out: &mut String) {
    let name = |p: Option<usize>, l: usize| match p {
        Some(p) => format!("{}:{}", PREFIXES[p].0, LOCALS[l]),
        None => LOCALS[l].to_string(),
    };
    let quote = if style.single_quotes { '\'' } else { '"' };
    let _ = write!(out, "<{}", name(e.prefix, e.local));
    let mut inner = scope;
    let mut declared = [false; 3];
    for &(p, n) in &e.declarations {
        inner[p] = n;
        declared[p] = true;
    }
    let mut attributes: Vec<(String, String)> = e
        .attributes
        .iter()
        .map(|(p, l, v)| (name(*p, *l), v.clone()))
        .collect();
    for (i, (p, namespaces)) in PREFIXES.iter().enumerate() {
        // Declared here, or bound at the root, or re-declared to what is already in scope.
        if declared[i] || root || style.redundant_declarations {
            attributes.push((format!("xmlns:{p}"), namespaces[inner[i]].into()));
        }
    }
    if let Some(d) = e.default {
        attributes.push(("xmlns".into(), DEFAULTS[d].into()));
    }
    if style.reverse_attributes {
        attributes.reverse();
    }
    for (n, v) in &attributes {
        let _ = write!(out, " {n}={quote}");
        escape(v, style, quote, out);
        out.push(quote);
    }
    if e.children.is_empty() && style.self_close_empty {
        out.push_str("/>");
        return;
    }
    out.push('>');
    for child in &e.children {
        match child {
            Content::Text(t) => escape(t, style, '\0', out),
            Content::Element(c) => write_element(c, style, inner, false, out),
        }
    }
    let _ = write!(out, "</{}>", name(e.prefix, e.local));
}

fn serialize(e: &Element, style: Style) -> String {
    let mut out = String::new();
    write_element(e, style, [0; 3], true, &mut out);
    out
}

fn c14n(xml: &str) -> Vec<u8> {
    let doc =
        Document::parse(xml.as_bytes(), &Limits::TSL).unwrap_or_else(|e| panic!("{e}\n{xml}"));
    doc.exc_c14n().unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn tslsig_016_canonical_form_is_a_fixed_point(e in element(), s in style()) {
        let once = c14n(&serialize(&e, s));
        let twice = c14n(std::str::from_utf8(&once).unwrap());
        prop_assert_eq!(once, twice);
    }

    #[test]
    fn tslsig_016_canonical_form_ignores_how_a_document_is_written(e in element(), s in style(), t in style()) {
        prop_assert_eq!(c14n(&serialize(&e, s)), c14n(&serialize(&e, t)));
    }
}
