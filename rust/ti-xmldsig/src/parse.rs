//! TSLSIG-001: the input is well-formed XML 1.0 in UTF-8 without a DTD, within limits.

use alloc::format;

use roxmltree::{Node, ParsingOptions};

use crate::Error;

/// Bounds on the input, checked before anything else looks at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Size of the input in bytes.
    pub max_bytes: usize,
    /// Nesting depth of elements; the document element has depth 1.
    pub max_depth: usize,
    /// Attributes on one element, namespace declarations not counted.
    pub max_attributes: usize,
    /// Namespaces in scope at one element.
    pub max_namespaces: usize,
    /// Nodes of the tree: elements, text, comments, processing instructions.
    pub max_nodes: u32,
}

impl Limits {
    /// The limits of TSLSIG-001, far above what TSLs need: the published ones and
    /// GemLibPki's are below 1 MiB, with about 7000 elements nested 12 deep and at most 3
    /// attributes on one.
    pub const TSL: Limits = Limits {
        max_bytes: 16 * 1024 * 1024,
        max_depth: 64,
        max_attributes: 64,
        max_namespaces: 64,
        max_nodes: 4_000_000,
    };
}

/// A parsed document: a strict, read-only tree that still knows the source text, so the
/// namespace prefixes canonicalization has to render can be read back from it.
pub struct Document<'a> {
    pub(crate) tree: roxmltree::Document<'a>,
}

impl core::fmt::Debug for Document<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Document")
            .field("root", &self.tree.root_element().tag_name().name())
            .finish_non_exhaustive()
    }
}

impl<'a> Document<'a> {
    /// Parses `xml` under `limits` (TSLSIG-001).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::NotWellFormed`](crate::ErrorKind::NotWellFormed) if the input is not
    /// UTF-8, declares another encoding or XML version, is not well-formed, has a
    /// document type declaration, or exceeds a limit.
    pub fn parse(xml: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        if xml.len() > limits.max_bytes {
            return Err(Error::not_well_formed(format!(
                "{} bytes exceed the limit of {}",
                xml.len(),
                limits.max_bytes
            )));
        }
        let text = core::str::from_utf8(xml)
            .map_err(|e| Error::not_well_formed(format!("not UTF-8: {e}")))?;
        check_declaration(text.strip_prefix('\u{feff}').unwrap_or(text))?;
        // The parser recurses once per nesting level, so the depth must be bounded
        // before it runs.
        check_depth(xml, limits.max_depth)?;
        let options = ParsingOptions {
            allow_dtd: false,
            nodes_limit: limits.max_nodes,
            ..ParsingOptions::default()
        };
        let tree = roxmltree::Document::parse_with_options(text, options)
            .map_err(|e| Error::not_well_formed(format!("{e}")))?;
        let document = Document { tree };
        document.check_shape(limits)?;
        Ok(document)
    }

    /// Depth, attribute and namespace counts, and that every element's and attribute's
    /// name as written in the source agrees with the tree.
    fn check_shape(&self, limits: &Limits) -> Result<(), Error> {
        let mut stack = alloc::vec![(self.tree.root_element(), 1usize)];
        while let Some((node, depth)) = stack.pop() {
            if depth > limits.max_depth {
                return Err(Error::not_well_formed(format!(
                    "elements nest deeper than {}",
                    limits.max_depth
                )));
            }
            if node.attributes().len() > limits.max_attributes {
                return Err(Error::not_well_formed(format!(
                    "<{}> has more than {} attributes",
                    node.tag_name().name(),
                    limits.max_attributes
                )));
            }
            if node.namespaces().len() > limits.max_namespaces {
                return Err(Error::not_well_formed(format!(
                    "<{}> has more than {} namespaces in scope",
                    node.tag_name().name(),
                    limits.max_namespaces
                )));
            }
            self.element_qname(node)?;
            for attribute in node.attributes() {
                self.attribute_qname(&attribute)?;
            }
            stack.extend(
                node.children()
                    .filter(Node::is_element)
                    .map(|c| (c, depth.saturating_add(1))),
            );
        }
        Ok(())
    }

    /// The element's name as written, `prefix:local` or `local`.
    pub(crate) fn element_qname(&self, node: Node<'_, 'a>) -> Result<&'a str, Error> {
        let text = self.tree.input_text();
        let start = node.range().start.saturating_add(1);
        let tail = text
            .get(start..)
            .ok_or_else(|| Error::not_well_formed("element outside the input"))?;
        let end = tail
            .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
            .unwrap_or(tail.len());
        let qname = tail.get(..end).unwrap_or_default();
        qname_matches(qname, node.tag_name().name())
    }

    /// The attribute's name as written, `prefix:local` or `local`.
    pub(crate) fn attribute_qname(
        &self,
        attribute: &roxmltree::Attribute<'_, 'a>,
    ) -> Result<&'a str, Error> {
        let qname = self
            .tree
            .input_text()
            .get(attribute.range_qname())
            .ok_or_else(|| Error::not_well_formed("attribute outside the input"))?;
        qname_matches(qname, attribute.name())
    }
}

/// The part of a name as written after its last `:`.
pub(crate) fn local_part(qname: &[u8]) -> &[u8] {
    match qname.iter().rposition(|b| *b == b':') {
        Some(colon) => qname.get(colon.saturating_add(1)..).unwrap_or_default(),
        None => qname,
    }
}

/// `qname`, if its local part is `local`. Guards the source positions the prefixes are
/// read from against any disagreement with the parsed tree.
fn qname_matches<'a>(qname: &'a str, local: &str) -> Result<&'a str, Error> {
    if local_part(qname.as_bytes()) == local.as_bytes() {
        Ok(qname)
    } else {
        Err(Error::not_well_formed(format!(
            "name {qname:?} does not match the parsed name {local:?}"
        )))
    }
}

/// Rejects input whose elements nest deeper than `max_depth`, without building a tree.
///
/// A lexical scan: it counts start tags and end tags outside comments, CDATA sections,
/// processing instructions and quoted attribute values, the only places a `<` or `>` can
/// occur without opening or closing an element. It never counts fewer levels than the
/// parser descends; whether the input is well-formed is left to the parser.
fn check_depth(xml: &[u8], max_depth: usize) -> Result<(), Error> {
    if nests_deeper(xml, max_depth) {
        Err(Error::not_well_formed(format!(
            "elements nest deeper than {max_depth}"
        )))
    } else {
        Ok(())
    }
}

/// Whether elements in `xml` nest deeper than `max_depth`, by the lexical scan of
/// [`check_depth`].
pub(crate) fn nests_deeper(xml: &[u8], max_depth: usize) -> bool {
    let mut depth = 0usize;
    let mut rest = xml;
    while let Some(lt) = memchr_lt(rest) {
        rest = rest.get(lt..).unwrap_or_default();
        if let Some(after) = rest.strip_prefix(b"<!--") {
            rest = skip_past(after, b"-->");
        } else if let Some(after) = rest.strip_prefix(b"<![CDATA[") {
            rest = skip_past(after, b"]]>");
        } else if let Some(after) = rest.strip_prefix(b"<?") {
            rest = skip_past(after, b"?>");
        } else if let Some(after) = rest.strip_prefix(b"</") {
            depth = depth.saturating_sub(1);
            rest = after;
        } else if let Some(after) = rest.strip_prefix(b"<!") {
            rest = after;
        } else {
            let (after, empty) = skip_tag(rest.get(1..).unwrap_or_default());
            rest = after;
            if depth >= max_depth {
                return true;
            }
            if !empty {
                depth = depth.saturating_add(1);
            }
        }
    }
    false
}

fn memchr_lt(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|b| *b == b'<')
}

/// The input after the first `end`, or nothing if there is none.
fn skip_past<'b>(bytes: &'b [u8], end: &[u8]) -> &'b [u8] {
    bytes
        .windows(end.len())
        .position(|w| w == end)
        .and_then(|i| bytes.get(i.saturating_add(end.len())..))
        .unwrap_or_default()
}

/// The input after a start tag's `>`, honouring quoted attribute values, and whether the
/// tag was empty (`/>`).
fn skip_tag(bytes: &[u8]) -> (&[u8], bool) {
    let mut quote = None;
    let mut previous = 0u8;
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => {
                return (
                    bytes.get(i.saturating_add(1)..).unwrap_or_default(),
                    previous == b'/',
                );
            }
            None => {}
        }
        previous = b;
    }
    (&[], false)
}

/// The XML declaration, if present, names version 1.0 and no encoding but UTF-8. The
/// parser checks the declaration's syntax but not these values.
fn check_declaration(text: &str) -> Result<(), Error> {
    let Some(rest) = text.strip_prefix("<?xml") else {
        return Ok(());
    };
    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        // `<?xml-stylesheet …?>` and the like: a processing instruction, not the declaration.
        return Ok(());
    }
    let declaration = rest
        .find("?>")
        .and_then(|end| rest.get(..end))
        .ok_or_else(|| Error::not_well_formed("unterminated XML declaration"))?;
    match pseudo_attribute(declaration, "version") {
        Some("1.0") => {}
        Some(v) => {
            return Err(Error::not_well_formed(format!(
                "XML version {v:?}, not 1.0"
            )));
        }
        None => return Err(Error::not_well_formed("XML declaration without version")),
    }
    match pseudo_attribute(declaration, "encoding") {
        None => Ok(()),
        Some(e) if e.eq_ignore_ascii_case("UTF-8") => Ok(()),
        Some(e) => Err(Error::not_well_formed(format!("encoding {e:?}, not UTF-8"))),
    }
}

/// The value of `name="…"` or `name='…'` in an XML declaration.
fn pseudo_attribute<'a>(declaration: &'a str, name: &str) -> Option<&'a str> {
    let after = declaration.split_once(name)?.1.trim_start();
    let after = after.strip_prefix('=')?.trim_start();
    let quote = after.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let value = after.get(1..)?;
    value.split_once(quote).map(|(v, _)| v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;
    use alloc::string::String;

    fn parse(xml: &str) -> Result<(), Error> {
        Document::parse(xml.as_bytes(), &Limits::TSL).map(|_| ())
    }

    fn rejected(xml: &str) -> String {
        let e = parse(xml).expect_err(xml);
        assert_eq!(e.kind(), ErrorKind::NotWellFormed, "{e}");
        assert_eq!(e.rule(), "TSLSIG-001");
        e.detail().into()
    }

    #[test]
    fn tslsig_001_accepts_plain_documents() {
        parse("<a/>").unwrap();
        parse("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a/>").unwrap();
        parse("<?xml version='1.0' encoding='utf-8' standalone='yes'?><a/>").unwrap();
        parse("\u{feff}<?xml version=\"1.0\"?><a/>").unwrap();
        parse("<?xml-stylesheet href=\"x\"?><a/>").unwrap();
        parse("<!-- before --><?pi x?><a xmlns:p=\"urn:p\" p:b=\"1\"><p:c/></a><!-- after -->")
            .unwrap();
    }

    #[test]
    fn tslsig_001_rejects_dtd_and_entities() {
        rejected("<!DOCTYPE a><a/>");
        rejected("<!DOCTYPE a [<!ENTITY e \"x\">]><a>&e;</a>");
        rejected("<!DOCTYPE a SYSTEM \"file:///etc/passwd\"><a/>");
        rejected("<a>&e;</a>");
    }

    #[test]
    fn tslsig_001_rejects_other_versions_and_encodings() {
        rejected("<?xml version=\"1.1\"?><a/>");
        rejected("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>");
        rejected("<?xml encoding=\"UTF-8\"?><a/>");
        let e = Document::parse(b"<a>\xff</a>", &Limits::TSL).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotWellFormed);
    }

    #[test]
    fn tslsig_001_rejects_malformed_documents() {
        rejected("");
        rejected("<a>");
        rejected("<a></b>");
        rejected("<a b=\"1\" b=\"2\"/>");
        rejected("<p:a/>");
        rejected("<a/><b/>");
        rejected("<a><!-- x -- y --></a>");
        rejected("<a>\u{1}</a>");
    }

    #[test]
    fn tslsig_001_enforces_limits() {
        let limits = Limits {
            max_bytes: 8,
            ..Limits::TSL
        };
        assert!(Document::parse(b"<a></a>  ", &limits).is_err());
        assert!(Document::parse(b"<a></a> ", &limits).is_ok());

        let limits = Limits {
            max_depth: 3,
            ..Limits::TSL
        };
        assert!(Document::parse(b"<a><b><c/></b></a>", &limits).is_ok());
        let detail = Document::parse(b"<a><b><c><d/></c></b></a>", &limits).unwrap_err();
        assert!(detail.detail().contains("deeper"), "{detail}");

        let limits = Limits {
            max_attributes: 2,
            ..Limits::TSL
        };
        assert!(Document::parse(b"<a x=\"1\" y=\"2\" xmlns:p=\"urn:p\"/>", &limits).is_ok());
        assert!(Document::parse(b"<a><b x=\"1\" y=\"2\" z=\"3\"/></a>", &limits).is_err());

        let limits = Limits {
            max_namespaces: 1,
            ..Limits::TSL
        };
        assert!(Document::parse(b"<a xmlns:p=\"urn:p\"/>", &limits).is_ok());
        assert!(
            Document::parse(b"<a xmlns:p=\"urn:p\"><b xmlns:q=\"urn:q\"/></a>", &limits).is_err()
        );

        let limits = Limits {
            max_nodes: 3,
            ..Limits::TSL
        };
        assert!(Document::parse(b"<a><b/><c/><d/></a>", &limits).is_err());
    }

    #[test]
    fn deep_nesting_is_rejected_without_recursion() {
        let depth = 100_000;
        let xml = "<a>".repeat(depth) + &"</a>".repeat(depth);
        assert!(rejected(&xml).contains("deeper"));
    }

    #[test]
    fn depth_scan_skips_markup_that_does_not_nest() {
        let limits = Limits {
            max_depth: 2,
            ..Limits::TSL
        };
        let ok = [
            "<a><b/></a>",
            "<a><b x=\"c>\" y='/>'/></a>",
            "<a><!-- <b><c><d> --><b/></a>",
            "<a><![CDATA[<b><c><d>]]><b/></a>",
            "<a><?pi <b><c><d>?><b/></a>",
            "<a><b></b><b></b><b/></a>",
        ];
        for xml in ok {
            assert!(check_depth(xml.as_bytes(), 2).is_ok(), "{xml}");
            assert!(Document::parse(xml.as_bytes(), &limits).is_ok(), "{xml}");
        }
        for xml in ["<a><b><c/></b></a>", "<a><b x='>'><c></c></b></a>"] {
            assert!(check_depth(xml.as_bytes(), 2).is_err(), "{xml}");
        }
    }

    #[test]
    fn qnames_are_read_from_the_source() {
        let xml = "<p:a xmlns:p=\"urn:p\" xmlns=\"urn:d\"\n  p:x = 'v' y=\"w\"><b/><p:c\t/></p:a>";
        let doc = Document::parse(xml.as_bytes(), &Limits::TSL).unwrap();
        let root = doc.tree.root_element();
        assert_eq!(doc.element_qname(root).unwrap(), "p:a");
        let names: alloc::vec::Vec<_> = root
            .attributes()
            .map(|a| doc.attribute_qname(&a).unwrap())
            .collect();
        assert_eq!(names, ["p:x", "y"]);
        let children: alloc::vec::Vec<_> = root
            .children()
            .map(|c| doc.element_qname(c).unwrap())
            .collect();
        assert_eq!(children, ["b", "p:c"]);
    }
}
