//! TSLSIG-016: Exclusive XML Canonicalization 1.0, without comments.
//!
//! The node sets XMLDSig needs here are a whole document minus one subtree (the
//! enveloped-signature transform of a `URI=""` reference) and an element with its
//! descendants (a same-document `#id` reference, and `SignedInfo`). Comments are never
//! part of either. Section numbers refer to Exc-C14N (`xml-exc-c14n`) and to the C14N 1.0
//! rules it builds on (`xml-c14n`).

use alloc::format;
use alloc::vec::Vec;

use roxmltree::{Node, NodeId, NodeType};

use crate::{Document, Error, ErrorKind};

/// The reference C14N 1.0 §2.3 ("Text Nodes") writes for a byte of character data,
/// `None` to copy it. Every replaced character is ASCII and UTF-8 encodes non-ASCII
/// characters with bytes ≥ 0x80 only, so a byte-wise map is the character-wise one.
pub(crate) fn text_reference(byte: u8) -> Option<&'static [u8]> {
    match byte {
        b'&' => Some(b"&amp;"),
        b'<' => Some(b"&lt;"),
        b'>' => Some(b"&gt;"),
        b'\r' => Some(b"&#xD;"),
        _ => None,
    }
}

/// As [`text_reference`], for attribute values (C14N 1.0 §2.3, "Attribute Nodes").
pub(crate) fn attribute_reference(byte: u8) -> Option<&'static [u8]> {
    match byte {
        b'&' => Some(b"&amp;"),
        b'<' => Some(b"&lt;"),
        b'"' => Some(b"&quot;"),
        b'\t' => Some(b"&#x9;"),
        b'\n' => Some(b"&#xA;"),
        b'\r' => Some(b"&#xD;"),
        _ => None,
    }
}

/// Appends `text` as character data.
pub(crate) fn escape_text(text: &str, out: &mut Vec<u8>) {
    escape(text, text_reference, out);
}

/// Appends `value` as an attribute value between double quotes.
pub(crate) fn escape_attribute(value: &str, out: &mut Vec<u8>) {
    escape(value, attribute_reference, out);
}

fn escape(text: &str, reference: fn(u8) -> Option<&'static [u8]>, out: &mut Vec<u8>) {
    for &byte in text.as_bytes() {
        match reference(byte) {
            Some(r) => out.extend_from_slice(r),
            None => out.push(byte),
        }
    }
}

/// A namespace declaration of the output: prefix (`""` for the default namespace) and
/// namespace name.
type Declaration<'a> = (&'a str, &'a str);

/// The namespace declarations an element renders, given those in effect in the output
/// from its output ancestors (`rendered`, innermost last): Exc-C14N §3, "visibly
/// utilized" prefixes only, and only where the output does not already bind the prefix
/// to the same namespace.
///
/// `utilized` lists the prefixes the element and its attributes are written with, `""`
/// for an unprefixed element; `in_scope` resolves a prefix to its namespace in the
/// source, `""` for an absent default namespace. The result is sorted by prefix, the
/// default namespace first (C14N 1.0 §2.3, "Namespace Nodes").
pub(crate) fn namespaces_to_render<'a>(
    utilized: &[&'a str],
    in_scope: impl Fn(&str) -> &'a str,
    rendered: &[Declaration<'a>],
) -> Vec<Declaration<'a>> {
    let mut declarations: Vec<Declaration<'a>> = Vec::new();
    for &prefix in utilized {
        if prefix == "xml" || declarations.iter().any(|(p, _)| *p == prefix) {
            continue;
        }
        let namespace = in_scope(prefix);
        let in_output = rendered
            .iter()
            .rev()
            .find(|(p, _)| *p == prefix)
            .map(|(_, n)| *n);
        let render = if prefix.is_empty() && namespace.is_empty() {
            // An unprefixed element without a default namespace undoes a non-empty
            // default the output would otherwise give it.
            in_output.is_some_and(|n| !n.is_empty())
        } else {
            in_output != Some(namespace)
        };
        if render {
            // Kept sorted as it grows; an element utilizes only a handful of prefixes.
            let at = declarations
                .iter()
                .position(|(p, _)| *p > prefix)
                .unwrap_or(declarations.len());
            declarations.insert(at, (prefix, namespace));
        }
    }
    declarations
}

/// What to canonicalize.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Subset {
    /// The whole document without the subtree at `omit`, if any: the enveloped-signature
    /// transform followed by canonicalization.
    Document { omit: Option<NodeId> },
    /// An element and its descendants.
    Element(NodeId),
}

impl<'a> Document<'a> {
    /// The Exclusive C14N 1.0 form (without comments) of the whole document.
    ///
    /// # Errors
    ///
    /// None for a parsed document; the result type covers inconsistencies between the
    /// source and the tree, which parsing already rules out.
    pub fn exc_c14n(&self) -> Result<Vec<u8>, Error> {
        self.canonicalize(Subset::Document { omit: None })
    }

    /// The Exclusive C14N 1.0 form (without comments) of the element whose attribute `Id`
    /// is `id`, as a same-document reference `#id` selects it.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Signature`](crate::ErrorKind::Signature) if no element or more than one
    /// has that `Id`.
    pub fn exc_c14n_by_id(&self, id: &str) -> Result<Vec<u8>, Error> {
        let element = self.element_by_id(id)?;
        self.canonicalize(Subset::Element(element.id()))
    }

    /// The Exclusive C14N 1.0 form (without comments) of the one element named `local` in
    /// the namespace `namespace` (`""` for none), with its descendants.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Signature`](crate::ErrorKind::Signature) if no element or more than one
    /// has that name.
    pub fn exc_c14n_by_name(&self, namespace: &str, local: &str) -> Result<Vec<u8>, Error> {
        let element = self.element_by_name(namespace, local, "TSLSIG-016")?;
        self.canonicalize(Subset::Element(element.id()))
    }

    /// The one element named `local` in `namespace`; `rule` names the rule that requires
    /// exactly one.
    pub(crate) fn element_by_name(
        &self,
        namespace: &str,
        local: &str,
        rule: &'static str,
    ) -> Result<Node<'_, 'a>, Error> {
        let mut found = self.tree.descendants().filter(|n| {
            n.is_element()
                && n.tag_name().name() == local
                && n.tag_name().namespace().unwrap_or_default() == namespace
        });
        match (found.next(), found.next()) {
            (Some(element), None) => Ok(element),
            (None, _) => Err(Error::new(
                ErrorKind::Signature,
                rule,
                format!("no element {local} in {namespace:?}"),
            )),
            (Some(_), Some(_)) => Err(Error::new(
                ErrorKind::Signature,
                rule,
                format!("several elements {local} in {namespace:?}"),
            )),
        }
    }

    /// The one element whose attribute `Id` (without namespace) is `id`.
    pub(crate) fn element_by_id(&self, id: &str) -> Result<Node<'_, 'a>, Error> {
        let mut found = self
            .tree
            .descendants()
            .filter(|n| n.is_element() && n.attribute("Id") == Some(id));
        match (found.next(), found.next()) {
            (Some(element), None) => Ok(element),
            (None, _) => Err(Error::new(
                ErrorKind::Signature,
                "TSLSIG-014",
                format!("no element has Id {id:?}"),
            )),
            (Some(_), Some(_)) => Err(Error::new(
                ErrorKind::Signature,
                "TSLSIG-014",
                format!("several elements have Id {id:?}"),
            )),
        }
    }

    pub(crate) fn canonicalize(&self, subset: Subset) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match subset {
            Subset::Document { omit } => {
                let mut after_root = false;
                for child in self.tree.root().children() {
                    match child.node_type() {
                        NodeType::Element => {
                            self.element(child, omit, &mut out)?;
                            after_root = true;
                        }
                        NodeType::PI => {
                            // C14N 1.0 §2.3: a line break separates processing
                            // instructions outside the document element from it.
                            if after_root {
                                out.push(b'\n');
                            }
                            processing_instruction(child, &mut out);
                            if !after_root {
                                out.push(b'\n');
                            }
                        }
                        _ => {}
                    }
                }
            }
            Subset::Element(id) => {
                let node = self
                    .tree
                    .get_node(id)
                    .ok_or_else(|| Error::not_well_formed("node of another document"))?;
                self.element(node, None, &mut out)?;
            }
        }
        Ok(out)
    }

    /// Canonicalizes `apex` and its descendants except the subtree at `omit`. Iterative,
    /// so depth costs heap, not stack.
    fn element<'d>(
        &'d self,
        apex: Node<'d, 'a>,
        omit: Option<NodeId>,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        enum Step<'d, 'a> {
            Enter(Node<'d, 'a>),
            Leave(&'d str, usize),
        }
        let mut rendered: Vec<Declaration<'d>> = Vec::new();
        let mut steps = alloc::vec![Step::Enter(apex)];
        while let Some(step) = steps.pop() {
            match step {
                Step::Leave(qname, rendered_before) => {
                    out.extend_from_slice(b"</");
                    out.extend_from_slice(qname.as_bytes());
                    out.push(b'>');
                    rendered.truncate(rendered_before);
                }
                Step::Enter(node) if Some(node.id()) == omit => {}
                Step::Enter(node) => match node.node_type() {
                    NodeType::Element => {
                        let rendered_before = rendered.len();
                        let qname = self.start_tag(node, &mut rendered, out)?;
                        steps.push(Step::Leave(qname, rendered_before));
                        let children: Vec<_> = node.children().collect();
                        steps.extend(children.into_iter().rev().map(Step::Enter));
                    }
                    NodeType::Text => escape_text(node.text().unwrap_or_default(), out),
                    NodeType::PI => processing_instruction(node, out),
                    NodeType::Comment | NodeType::Root => {}
                },
            }
        }
        Ok(())
    }

    /// Writes the start tag of `element` and adds the namespace declarations it renders
    /// to `rendered`. Returns the element's name as written.
    fn start_tag<'d>(
        &'d self,
        element: Node<'d, 'a>,
        rendered: &mut Vec<Declaration<'d>>,
        out: &mut Vec<u8>,
    ) -> Result<&'d str, Error> {
        let qname = self.element_qname(element)?;
        let mut utilized = alloc::vec![prefix(qname)];
        // (namespace, local name) is the sort key of C14N 1.0 §2.3; no namespace sorts
        // first because the empty string does.
        let mut attributes = Vec::new();
        for attribute in element.attributes() {
            let written = self.attribute_qname(&attribute)?;
            if written.contains(':') {
                utilized.push(prefix(written));
            }
            attributes.push((
                attribute.namespace().unwrap_or_default(),
                attribute.name(),
                written,
                attribute.value(),
            ));
        }
        let declarations = namespaces_to_render(
            &utilized,
            |p| {
                element
                    .lookup_namespace_uri((!p.is_empty()).then_some(p))
                    .unwrap_or_default()
            },
            rendered,
        );
        attributes.sort_unstable_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

        out.push(b'<');
        out.extend_from_slice(qname.as_bytes());
        for (prefix, namespace) in &declarations {
            out.extend_from_slice(b" xmlns");
            if !prefix.is_empty() {
                out.push(b':');
                out.extend_from_slice(prefix.as_bytes());
            }
            out.extend_from_slice(b"=\"");
            escape_attribute(namespace, out);
            out.push(b'"');
        }
        for (_, _, written, value) in &attributes {
            out.push(b' ');
            out.extend_from_slice(written.as_bytes());
            out.extend_from_slice(b"=\"");
            escape_attribute(value, out);
            out.push(b'"');
        }
        out.push(b'>');
        rendered.extend(declarations);
        Ok(qname)
    }
}

/// The prefix of a name as written, `""` if it has none.
fn prefix(qname: &str) -> &str {
    qname.split_once(':').map_or("", |(p, _)| p)
}

fn processing_instruction(node: Node<'_, '_>, out: &mut Vec<u8>) {
    if let Some(pi) = node.pi() {
        out.extend_from_slice(b"<?");
        out.extend_from_slice(pi.target.as_bytes());
        if let Some(value) = pi.value.filter(|v| !v.is_empty()) {
            out.push(b' ');
            out.extend_from_slice(value.as_bytes());
        }
        out.extend_from_slice(b"?>");
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::string::String;
    use alloc::vec;

    use base64ct::{Base64, Encoding};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::Limits;

    fn c14n(xml: &str) -> String {
        let doc = Document::parse(xml.as_bytes(), &Limits::TSL).unwrap();
        String::from_utf8(doc.exc_c14n().unwrap()).unwrap()
    }

    #[test]
    fn tslsig_016_escapes_text() {
        let mut out = Vec::new();
        escape_text("a&b<c>d\re\"f'g\th\ni", &mut out);
        assert_eq!(out, b"a&amp;b&lt;c&gt;d&#xD;e\"f'g\th\ni");
    }

    #[test]
    fn tslsig_016_escapes_attribute_values() {
        let mut out = Vec::new();
        escape_attribute("a&b<c>d\re\"f'g\th\ni", &mut out);
        assert_eq!(out, b"a&amp;b&lt;c>d&#xD;e&quot;f'g&#x9;h&#xA;i");
    }

    #[test]
    fn tslsig_016_renders_only_visibly_utilized_namespaces() {
        let in_scope = |p: &str| match p {
            "" => "urn:default",
            "a" => "urn:a",
            "b" => "urn:b",
            _ => "",
        };
        assert_eq!(
            namespaces_to_render(&["b", "", "a", "b"], in_scope, &[]),
            vec![("", "urn:default"), ("a", "urn:a"), ("b", "urn:b")]
        );
        // Already in effect in the output with the same namespace.
        assert_eq!(
            namespaces_to_render(&["a", ""], in_scope, &[("a", "urn:a"), ("", "urn:default")]),
            vec![]
        );
        // In effect with another namespace: the innermost declaration counts.
        assert_eq!(
            namespaces_to_render(&["a"], in_scope, &[("a", "urn:a"), ("a", "urn:other")]),
            vec![("a", "urn:a")]
        );
        // `xml` is never declared.
        assert_eq!(namespaces_to_render(&["xml"], in_scope, &[]), vec![]);
    }

    #[test]
    fn tslsig_016_undeclares_the_default_namespace_only_where_the_output_has_one() {
        let none = |_: &str| "";
        assert_eq!(namespaces_to_render(&[""], none, &[]), vec![]);
        assert_eq!(namespaces_to_render(&[""], none, &[("", "")]), vec![]);
        assert_eq!(
            namespaces_to_render(&[""], none, &[("", "urn:d")]),
            vec![("", "")]
        );
    }

    /// The rule of Exc-C14N §3 over its whole bounded domain: every binding of the
    /// default namespace and two prefixes to one of two namespaces or none, every output
    /// context of up to two declarations, every element utilizing up to two prefixes (with
    /// `xml`). After the element's declarations, each prefix it utilizes is bound in the
    /// output as in the source (an empty default namespace may also stay absent); `xml`
    /// is never declared; nothing is declared without need; the result is sorted.
    #[test]
    fn tslsig_016_namespace_rule_holds_on_the_bounded_domain_exhaustively() {
        const PREFIXES: [&str; 4] = ["", "a", "b", "xml"];
        const NAMESPACES: [&str; 3] = ["", "urn:1", "urn:2"];
        let in_effect = |declarations: &[Declaration<'static>], prefix: &str| {
            declarations
                .iter()
                .rev()
                .find(|(p, _)| *p == prefix)
                .map(|(_, n)| *n)
        };
        let declaration_space: Vec<Declaration<'static>> = (0..3)
            .flat_map(|p| (0..3).map(move |n| (PREFIXES[p], NAMESPACES[n])))
            .filter(|(p, n)| p.is_empty() || !n.is_empty())
            .collect();
        let mut contexts: Vec<Vec<Declaration<'static>>> = vec![vec![]];
        for d in &declaration_space {
            contexts.push(vec![*d]);
            for e in &declaration_space {
                contexts.push(vec![*d, *e]);
            }
        }
        let mut uses: Vec<Vec<&str>> = vec![vec![]];
        for p in PREFIXES {
            uses.push(vec![p]);
            for q in PREFIXES {
                uses.push(vec![p, q]);
            }
        }
        let mut cases = 0u32;
        for d in NAMESPACES {
            for a in NAMESPACES.into_iter().skip(1) {
                for b in NAMESPACES.into_iter().skip(1) {
                    let source = [d, a, b];
                    let in_scope = |p: &str| match p {
                        "" => source[0],
                        "a" => source[1],
                        "b" => source[2],
                        _ => "http://www.w3.org/XML/1998/namespace",
                    };
                    for rendered in &contexts {
                        for utilized in &uses {
                            cases += 1;
                            let declarations = namespaces_to_render(utilized, in_scope, rendered);
                            assert!(declarations.windows(2).all(|w| w[0].0 < w[1].0));
                            for (prefix, namespace) in &declarations {
                                assert_ne!(*prefix, "xml");
                                assert_eq!(*namespace, in_scope(prefix));
                                assert!(utilized.contains(prefix));
                                assert_ne!(in_effect(rendered, prefix), Some(*namespace));
                            }
                            let mut after = rendered.clone();
                            after.extend(declarations.iter().copied());
                            for prefix in utilized.iter().filter(|p| **p != "xml") {
                                let effective = in_effect(&after, prefix);
                                if prefix.is_empty() && in_scope(prefix).is_empty() {
                                    assert!(matches!(effective, None | Some("")));
                                } else {
                                    assert_eq!(effective, Some(in_scope(prefix)));
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 12 * 57 * 21);
    }

    #[test]
    fn tslsig_016_canonical_form() {
        assert_eq!(c14n("<a/>"), "<a></a>");
        assert_eq!(c14n("<a b='1' a=\"2\"/>"), "<a a=\"2\" b=\"1\"></a>");
        // A namespace declared on an ancestor is rendered where it is used.
        assert_eq!(
            c14n("<a xmlns:p=\"urn:p\"><b><p:c/></b><p:d/></a>"),
            "<a><b><p:c xmlns:p=\"urn:p\"></p:c></b><p:d xmlns:p=\"urn:p\"></p:d></a>"
        );
        // Redundant declarations of the TSL's kind disappear.
        assert_eq!(
            c14n("<n:a xmlns:n=\"urn:n\"><n:b xmlns:n=\"urn:n\"/></n:a>"),
            "<n:a xmlns:n=\"urn:n\"><n:b></n:b></n:a>"
        );
        // xml:* attributes are not inherited by exclusive canonicalization.
        assert_eq!(
            c14n("<a xml:lang=\"de\"><b/></a>"),
            "<a xml:lang=\"de\"><b></b></a>"
        );
        // Comments go, processing instructions stay, CDATA becomes text.
        assert_eq!(
            c14n("<a><!--x--><?p d?><![CDATA[<&>]]></a>"),
            "<a><?p d?>&lt;&amp;&gt;</a>"
        );
        // Line ends are normalized by the parser; a character reference survives.
        assert_eq!(c14n("<a>x\r\ny&#13;z</a>"), "<a>x\ny&#xD;z</a>");
    }

    #[test]
    fn tslsig_016_omits_a_subtree() {
        let xml = "<r xmlns=\"urn:r\"><a/><ds:S xmlns:ds=\"urn:ds\"><x/></ds:S><b/></r>";
        let doc = Document::parse(xml.as_bytes(), &Limits::TSL).unwrap();
        let signature = doc.element_by_name("urn:ds", "S", "test").unwrap();
        let out = doc
            .canonicalize(Subset::Document {
                omit: Some(signature.id()),
            })
            .unwrap();
        assert_eq!(out, b"<r xmlns=\"urn:r\"><a></a><b></b></r>");
    }

    #[test]
    fn tslsig_016_canonicalizes_a_subtree_in_its_namespace_context() {
        let xml =
            "<r xmlns=\"urn:r\" xmlns:p=\"urn:p\" xml:lang=\"de\"><p:a><b p:x=\"1\"/></p:a></r>";
        let doc = Document::parse(xml.as_bytes(), &Limits::TSL).unwrap();
        assert_eq!(
            String::from_utf8(doc.exc_c14n_by_name("urn:p", "a").unwrap()).unwrap(),
            "<p:a xmlns:p=\"urn:p\"><b xmlns=\"urn:r\" p:x=\"1\"></b></p:a>"
        );
    }

    /// The digests of both references of published TSLs and of GemLibPki's signer, over
    /// the forms this implementation computes.
    #[test]
    fn tslsig_016_reproduces_the_digests_of_published_tsls() {
        let real = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/tsl-xmldsig/testdata/tsl/real"
        );
        let mut checked = 0;
        for entry in std::fs::read_dir(real).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "xml") {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            let doc = Document::parse(&bytes, &Limits::TSL).unwrap();
            let ds = "http://www.w3.org/2000/09/xmldsig#";
            let signature = doc.element_by_name(ds, "Signature", "test").unwrap();
            let digests: Vec<_> = doc
                .tree
                .descendants()
                .filter(|n| {
                    n.tag_name().name() == "DigestValue"
                        && n.parent()
                            .is_some_and(|p| p.tag_name().name() == "Reference")
                })
                .map(|n| n.text().unwrap().trim())
                .collect();
            let content = doc
                .canonicalize(Subset::Document {
                    omit: Some(signature.id()),
                })
                .unwrap();
            assert_eq!(
                Base64::encode_string(&Sha256::digest(&content)),
                digests[0],
                "{}",
                path.display()
            );
            let target = doc
                .tree
                .descendants()
                .find(|n| {
                    n.attribute("Type")
                        .is_some_and(|t| t.ends_with("#SignedProperties"))
                })
                .and_then(|n| n.attribute("URI"))
                .unwrap();
            let properties = doc.exc_c14n_by_id(target.trim_start_matches('#')).unwrap();
            assert_eq!(
                Base64::encode_string(&Sha256::digest(&properties)),
                digests[1],
                "{}",
                path.display()
            );
            checked += 1;
        }
        assert!(checked >= 3);
    }
}
