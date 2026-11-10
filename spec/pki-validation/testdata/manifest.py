"""Writes manifest.json: the cases of spec/pki-validation over the files generate.sh made."""
import json
import pathlib

AT = "2026-01-01T00:00:00Z"
TRUST = {
    "ti": {"profile": "ti", "roots": ["ti-root.pem"],
           "tsl_cas": [{"cert": "ti-ca.pem", "types": ["C.FD.TLS-S", "C.ZD.TLS-S", "C.FD.TLS-C"]}]},
    "ti-no-tsl": {"profile": "ti", "roots": ["ti-root.pem"], "tsl_cas": None},
    "web": {"profile": "web", "roots": ["web-root.pem"]},
}
cases = []


def case(name, trust, chain, host, expect, rules, stapled=None, ocsp=None, crl=None, warnings=()):
    cases.append({
        "name": name, "trust": trust, "chain": chain, "host": host, "at": AT,
        "stapled_ocsp": stapled and f"ocsp/{stapled}.der",
        "responder_ocsp": ocsp and f"ocsp/{ocsp}.der",
        "crl": crl and f"crl/{crl}.der",
        "expect": expect, "warnings": list(warnings), "rules": rules,
    })


def ti(name, ee, host, expect, rules, stapled="good", **kw):
    chain = [f"{ee}.pem", "ti-ca.pem"]
    staple = None if stapled is None else (f"{ee}-{stapled}" if stapled in ("good",) else stapled)
    case(name, kw.pop("trust", "ti"), kw.pop("chain", chain), host, expect, rules, stapled=staple, **kw)


def web(name, ee, host, expect, rules, stapled="good", **kw):
    chain = [f"{ee}.pem", kw.pop("ca", "web-ca.pem")]
    staple = None if stapled is None else (f"{ee}-{stapled}" if stapled in ("good",) else stapled)
    case(name, kw.pop("trust", "web"), chain, host, expect, rules, stapled=staple, **kw)


# ti
ti("ti-cn-and-san", "ti-good", "svc.ti.test", "valid", ["TLSV-030", "TLSV-031", "TLSV-032"])
ti("ti-second-san", "ti-good", "ALT.ti.test.", "valid", ["TLSV-024", "TLSV-031"])
ti("ti-other-name", "ti-good", "other.ti.test", "name_mismatch", ["TLSV-024", "TLSV-031"])
ti("ti-cn-only", "ti-cn-only", "svc.ti.test", "valid", ["TLSV-031"])
ti("ti-wildcard", "ti-wildcard", "a.ti.test", "valid", ["TLSV-024", "TLSV-031"])
ti("ti-wildcard-two-labels", "ti-wildcard", "a.b.ti.test", "name_mismatch", ["TLSV-024"])
ti("ti-wildcard-no-label", "ti-wildcard", "ti.test", "name_mismatch", ["TLSV-024"])
ti("ti-zd", "ti-zd", "zd.ti.test", "valid", ["TLSV-030"])
ti("ti-client-type", "ti-tls-c", "svc.ti.test", "profile_type_mismatch", ["TLSV-030"])
ti("ti-client-eku", "ti-client-eku", "svc.ti.test", "key_usage_mismatch", ["TLSV-022"])
ti("ti-expired", "ti-expired", "svc.ti.test", "expired", ["TLSV-021"], stapled=None)
ti("ti-sha1", "ti-sha1", "svc.ti.test", "signature_algorithm_not_allowed", ["TLSV-023"])
ti("ti-p521", "ti-p521", "svc.ti.test", "key_not_admissible", ["TLSV-030"])
ti("ti-revoked", "ti-revoked", "svc.ti.test", "ocsp_revoked", ["TLSV-032"], stapled="ti-revoked-revoked")
ti("ti-responder-good", "ti-good", "svc.ti.test", "valid", ["TLSV-032"], stapled=None, ocsp="ti-good-good")
ti("ti-stale-staple", "ti-good", "svc.ti.test", "valid", ["TLSV-032"], stapled="ti-good-stale",
   ocsp="ti-good-good", warnings=["provided_ocsp_response_not_valid"])
ti("ti-wrong-hash-staple", "ti-good", "svc.ti.test", "ocsp_unavailable", ["TLSV-032"],
   stapled="ti-good-wrong-hash", warnings=["provided_ocsp_response_not_valid"])
ti("ti-no-responder", "ti-good", "svc.ti.test", "ocsp_unavailable", ["TLSV-032"], stapled=None)
ti("ti-unknown", "ti-good", "svc.ti.test", "ocsp_unknown", ["TLSV-032"], stapled=None, ocsp="ti-good-unknown")
ti("ti-no-tsl", "ti-good", "svc.ti.test", "trust_material_unavailable", ["TLSV-033"], trust="ti-no-tsl")
ti("ti-leaf-only", "ti-good", "svc.ti.test", "valid", ["TLSV-020"], chain=["ti-good.pem"])
ti("ti-extra-certificates", "ti-good", "svc.ti.test", "valid", ["TLSV-020"],
   chain=["ti-good.pem", "web-ca.pem", "ti-ca.pem", "web-root.pem"])
case("ti-public-certificate", "ti", ["web-p256.pem", "web-ca.pem", "web-root.pem"], "www.web.test",
     "chain_incomplete", ["TLSV-001", "TLSV-020", "TLSV-030"], stapled="web-p256-good")
# A path that reaches no anchor is chain_incomplete before its links are judged (TLSV-020 before TLSV-023).
case("ti-partial-path-weak-link", "ti", ["web-sha1.pem", "web-ca.pem"], "www.web.test",
     "chain_incomplete", ["TLSV-020", "TLSV-023"])

# web
web("web-p256", "web-p256", "www.web.test", "valid", ["TLSV-040", "TLSV-041", "TLSV-043", "TLSV-044"])
web("web-p384", "web-p384", "www.web.test", "valid", ["TLSV-041"])
web("web-rsa3072", "web-rsa3072", "www.web.test", "valid", ["TLSV-041", "TLSV-042"])
# TLSV-041's deviation from A_28976: RSA 2048 to 2999 bits is phased out, not refused.
web("web-rsa2048", "web-rsa2048", "www.web.test", "valid", ["TLSV-041"], warnings=["key_phased_out"])
web("web-p521", "web-p521", "www.web.test", "key_not_admissible", ["TLSV-041"])
web("web-weak-ca", "web-under-weak-ca", "www.web.test", "key_not_admissible", ["TLSV-042"],
    stapled=None, ca="web-ca-1024.pem")
web("web-cn-not-read", "web-p256", "other.web.test", "name_mismatch", ["TLSV-043"])
web("web-cn-only", "web-cn-only", "www.web.test", "name_mismatch", ["TLSV-043"])
web("web-wildcard", "web-wildcard", "a.web.test", "valid", ["TLSV-024", "TLSV-043"])
web("web-wildcard-two-labels", "web-wildcard", "a.b.web.test", "name_mismatch", ["TLSV-024"])
web("web-wildcard-no-label", "web-wildcard", "web.test", "name_mismatch", ["TLSV-024"])
web("web-partial-wildcard", "web-partial", "foo.web.test", "name_mismatch", ["TLSV-024"])
web("web-ip", "web-ip", "192.0.2.1", "valid", ["TLSV-024"])
web("web-other-ip", "web-ip", "192.0.2.2", "name_mismatch", ["TLSV-024"])
web("web-client-eku", "web-client-eku", "www.web.test", "key_usage_mismatch", ["TLSV-022"])
web("web-sha1", "web-sha1", "www.web.test", "signature_algorithm_not_allowed", ["TLSV-023"])
web("web-long", "web-long", "www.web.test", "validity_too_long", ["TLSV-045"])
web("web-expired", "web-expired", "www.web.test", "expired", ["TLSV-021"], stapled=None)
web("web-revoked", "web-revoked", "www.web.test", "revoked", ["TLSV-044"], stapled="web-revoked-revoked")
web("web-responder", "web-p256", "www.web.test", "valid", ["TLSV-044"], stapled=None, ocsp="web-p256-good")
web("web-crl-after-responder", "web-p256", "www.web.test", "valid", ["TLSV-044"], stapled=None,
    crl="web-ca-empty")
web("web-unknown-then-crl", "web-p256", "www.web.test", "valid", ["TLSV-044"], stapled=None,
    ocsp="web-p256-unknown", crl="web-ca-empty")
web("web-crl-only", "web-crl-only", "www.web.test", "valid", ["TLSV-044"], stapled=None, crl="web-ca-empty")
web("web-crl-revoked", "web-crl-revoked", "www.web.test", "revoked", ["TLSV-044"], stapled=None,
    crl="web-ca-revoked")
# TLSV-044's deviation from A_27857-02: no status is a warning, a revoked one still refuses.
web("web-no-status-source", "web-no-status", "www.web.test", "valid", ["TLSV-044"], stapled=None,
    warnings=["revocation_unavailable"])
web("web-sources-down", "web-p256", "www.web.test", "valid", ["TLSV-044"], stapled=None,
    warnings=["revocation_unavailable"])
web("web-unknown-only", "web-p256", "www.web.test", "valid", ["TLSV-044"], stapled=None,
    ocsp="web-p256-unknown", warnings=["revocation_unavailable"])
web("web-revoked-by-responder", "web-revoked", "www.web.test", "revoked", ["TLSV-044"], stapled=None,
    ocsp="web-revoked-revoked")
web("web-revoked-staple-before-crl", "web-revoked", "www.web.test", "revoked", ["TLSV-044"],
    stapled="web-revoked-revoked", crl="web-ca-empty")
web("web-rsa2048-no-status", "web-rsa2048", "www.web.test", "valid", ["TLSV-041", "TLSV-044"], stapled=None,
    warnings=["key_phased_out", "revocation_unavailable"])
case("web-ti-certificate", "web", ["ti-good.pem", "ti-ca.pem", "ti-root.pem"], "svc.ti.test",
     "chain_incomplete", ["TLSV-001", "TLSV-020", "TLSV-040"], stapled="ti-good-good")
case("web-partial-path-weak-link", "web", ["ti-sha1.pem", "ti-ca.pem"], "svc.ti.test",
     "chain_incomplete", ["TLSV-020", "TLSV-023"])

here = pathlib.Path(__file__).parent
for c in cases:
    for f in c["chain"] + [c["stapled_ocsp"], c["responder_ocsp"], c["crl"]]:
        assert f is None or (here / f).exists(), (c["name"], f)
(here / "manifest.json").write_text(json.dumps({"trust": TRUST, "cases": cases}, indent=1) + "\n")
print(len(cases), "cases")
