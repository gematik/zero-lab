# Canonicalization examples from the specifications

Inputs from Canonical XML 1.0 §3 (`c14n-3.*`) and Exclusive XML Canonicalization 1.0
§2.2 (`exc-c14n-2.2-*`), adapted where the profile forbids a construct: document type
declarations removed (3.1, 3.3, 3.4), the encoding declaration of 3.6 removed (only UTF-8
is accepted). Without a DTD, 3.4's attributes are all CDATA, so `normNames` and `normId`
keep their spaces, unlike in the C14N specification.

Expected outputs are Exclusive C14N 1.0 **without comments**:
- `<name>.c14n`: the whole document; produced by `xmllint --exc-c14n` (libxml2 2.13) and
  checked against the specifications' examples, except `c14n-3.1-pis-comments.c14n`, whose
  input has comments (xmllint keeps them) and which is the "uncommented" form of C14N 1.0
  §3.1;
- `<name>.elem2.c14n`: the subtree of the element `elem2`, the output Exc-C14N §2.2 gives
  for both documents.
