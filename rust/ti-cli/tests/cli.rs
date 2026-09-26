//! The `tir` binary as a user or an agent sees it: arguments, stdout, stderr, exit codes.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn tir(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tir"))
        .args(args)
        .env_remove("TI_FORMAT")
        .env_remove("TI_ENV")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR_FORCE")
        .output()
        .unwrap()
}

fn tir_with_stdin(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tir"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../ti-pki/tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn piped_output_is_markdown_and_text_on_request() {
    let file = fixture("admission-1.pem");
    let markdown = stdout(&tir(&["pki", "inspect", &file]));
    assert!(markdown.starts_with("## Subject\n"), "{markdown}");
    assert!(
        markdown.contains("| **type** | `C.HCI.AUT` |"),
        "{markdown}"
    );
    assert!(
        markdown.contains("**Arztpraxis Bernd Rosenstrauch TEST-ONLY**"),
        "{markdown}"
    );

    let text = stdout(&tir(&["--format", "text", "pki", "inspect", &file]));
    assert!(text.contains("  type           C.HCI.AUT"), "{text}");
    assert!(!text.contains('|'), "{text}");
}

#[test]
fn timestamps_in_the_system_zone() {
    let out = Command::new(env!("CARGO_BIN_EXE_tir"))
        .args([
            "--format",
            "text",
            "pki",
            "inspect",
            &fixture("admission-1.pem"),
        ])
        .env("TZ", "Europe/Berlin")
        .output()
        .unwrap();
    let text = stdout(&out);
    // notBefore 2023-11-09T23:00:00Z is midnight in Berlin.
    assert!(text.contains("2023-11-10 00:00:00 +01:00 (CET)"), "{text}");
}

#[test]
fn inspect_prints_plain_text_when_piped() {
    let out = tir(&["pki", "inspect", &fixture("admission-1.pem")]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("Arztpraxis Bernd Rosenstrauch TEST-ONLY"),
        "{text}"
    );
    assert!(text.contains("C.HCI.AUT"), "{text}");
    assert!(!text.contains('\x1b'), "no escape codes when piped");
}

#[test]
fn colors_can_be_forced_and_disabled() {
    let file = fixture("admission-1.pem");
    let forced = tir(&[
        "--format", "text", "--color", "always", "pki", "inspect", &file,
    ]);
    assert!(stdout(&forced).contains('\x1b'));
    let never = Command::new(env!("CARGO_BIN_EXE_tir"))
        .args(["--format", "text", "pki", "inspect", &file])
        .env("CLICOLOR_FORCE", "1")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(!stdout(&never).contains('\x1b'), "NO_COLOR wins");
}

#[test]
fn inspect_json_is_the_contract() {
    let out = tir(&[
        "--format",
        "json",
        "pki",
        "inspect",
        &fixture("admission-1.pem"),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1, "compact when piped");
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["schema"], 1);
    let cert = &json["certificates"][0];
    assert_eq!(cert["certificate_type"], "C.HCI.AUT");
    assert_eq!(cert["key"]["status"], "admissible");
    assert_eq!(cert["profile"]["name"], "smb-aut");
    assert_eq!(
        cert["admission"]["profession_oids"][0]["oid"],
        "1.2.276.0.76.4.50"
    );
    assert_eq!(cert["sha256"].as_str().unwrap().len(), 95);
}

#[test]
fn format_from_the_environment() {
    let out = Command::new(env!("CARGO_BIN_EXE_tir"))
        .args(["pki", "profiles", "list"])
        .env("TI_FORMAT", "json")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["profiles"].as_array().unwrap().len(), 4);
}

#[test]
fn stdin_pem_and_der() {
    let pem = std::fs::read(fixture("admission-1.pem")).unwrap();
    let from_pem = tir_with_stdin(&["pki", "inspect", "-"], &pem);
    assert_eq!(from_pem.status.code(), Some(0), "{}", stderr(&from_pem));
    assert!(stdout(&from_pem).contains("Arztpraxis Bernd Rosenstrauch"));
    let json = tir_with_stdin(&["--format", "json", "pki", "inspect", "-"], &pem);
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json["source"], "<stdin>");

    let der = ti_pki::parse_pem_certificates(&pem).unwrap()[0]
        .der()
        .to_vec();
    let from_der = tir_with_stdin(&["--format", "json", "pki", "inspect", "-"], &der);
    let json: serde_json::Value = serde_json::from_slice(&from_der.stdout).unwrap();
    assert_eq!(json["certificates"][0]["certificate_type"], "C.HCI.AUT");
}

#[test]
fn unreadable_input_is_exit_4_with_a_hint() {
    let out = tir(&["pki", "inspect", "/nonexistent/card.pem"]);
    assert_eq!(out.status.code(), Some(4));
    assert!(stdout(&out).is_empty());
    let err = stderr(&out);
    assert!(err.contains("cannot read /nonexistent/card.pem"), "{err}");
    assert!(err.contains("hint:"), "{err}");

    let json = tir(&[
        "--format",
        "json",
        "pki",
        "inspect",
        "/nonexistent/card.pem",
    ]);
    assert_eq!(json.status.code(), Some(4));
    let error: serde_json::Value = serde_json::from_slice(&json.stderr).unwrap();
    assert_eq!(error["schema"], 1);
    assert_eq!(error["error"]["kind"], "input_unreadable");
    assert!(error["error"]["hint"].is_string());

    let empty = tir_with_stdin(&["pki", "inspect", "-"], b"");
    assert_eq!(empty.status.code(), Some(4));
    assert!(stderr(&empty).contains("no certificate found"));
}

#[test]
fn profiles() {
    let list = stdout(&tir(&["pki", "profiles", "list"]));
    for name in ["epa-vau-aut", "idp-sig", "smb-aut", "zeta-guard-aut"] {
        assert!(list.contains(name), "{list}");
    }
    let describe = tir(&[
        "--format",
        "json",
        "pki",
        "profiles",
        "describe",
        "zeta-guard-aut",
    ]);
    let json: serde_json::Value = serde_json::from_slice(&describe.stdout).unwrap();
    assert_eq!(json["types"][0]["certificate_type"], "C.FD.AUT");
    assert_eq!(
        json["types"][0]["role_oids"][0]["oid"],
        "1.2.276.0.76.4.328"
    );

    let unknown = tir(&["pki", "profiles", "describe", "idp"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(
        stderr(&unknown).contains("smb-aut"),
        "lists the valid values"
    );
}

#[test]
fn http_options_are_validated_and_shown_with_verbose() {
    let dir = std::env::temp_dir().join("tir-cli-test-cache");
    let out = Command::new(env!("CARGO_BIN_EXE_tir"))
        .args([
            "-v",
            "-x",
            "http://user:secret@proxy:3128",
            "-m",
            "5",
            "pki",
            "profiles",
            "list",
        ])
        .env("TI_CACHE_DIR", &dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let err = stderr(&out);
    assert!(err.contains(&format!("cache {}", dir.display())), "{err}");
    assert!(err.contains("proxy http://***@proxy:3128"), "{err}");
    assert!(!err.contains("secret"), "{err}");
    assert!(err.contains("max 5s"), "{err}");

    for bad in [
        &["-x", "proxy:3128"][..],
        &["--max-time", "0"],
        &["--connect-timeout", "x"],
    ] {
        let args: Vec<&str> = bad
            .iter()
            .copied()
            .chain(["pki", "profiles", "list"])
            .collect();
        assert_eq!(tir(&args).status.code(), Some(2), "{bad:?}");
    }
}

#[test]
fn help_documents_exit_codes() {
    let help = tir(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    let text = stdout(&help);
    assert!(text.contains("Exit codes:"), "{text}");
    assert!(text.contains("HTTP options"), "{text}");
}

/// `tir … | head` must end quietly: a closed stdout is not an error.
#[test]
fn a_closed_pipe_is_not_an_error() {
    let pem = std::fs::read(fixture("admission-1.pem")).unwrap();
    // Enough certificates to overflow any pipe buffer.
    let many: Vec<u8> = std::iter::repeat_n(pem.as_slice(), 400)
        .flatten()
        .copied()
        .collect();
    let dir = std::env::temp_dir().join(format!("tir-pipe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("many.pem");
    std::fs::write(&file, &many).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_tir"))
        .args(["pki", "inspect"])
        .arg(&file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = [0u8; 16];
    child.stdout.take().unwrap().read_exact(&mut first).unwrap();
    // Dropping the read end closes the pipe while tir is still writing.
    let status = child.wait().unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(status.code(), Some(0), "{err}");
    assert!(err.is_empty(), "{err}");
}

fn verify_json(extra: &[&str]) -> (Option<i32>, serde_json::Value) {
    let ee = fixture("admission-1.pem");
    let mut args = vec!["--format", "json", "pki", "verify", ee.as_str()];
    args.extend_from_slice(extra);
    let out = tir(&args);
    (
        out.status.code(),
        serde_json::from_slice(&out.stdout).unwrap(),
    )
}

#[test]
fn verify_with_the_issuer_is_valid_but_says_revocation_was_not_checked() {
    let ca = fixture("smcb-ca51-test-only.pem");
    let (code, json) = verify_json(&["--issuer", &ca, "--at", "2026-06-01T00:00:00Z"]);
    assert_eq!(code, Some(0), "{json}");
    assert_eq!(json["schema"], 1);
    assert_eq!(json["valid"], true);
    assert_eq!(json["revocation_checked"], false);
    assert_eq!(json["at"], "2026-06-01T00:00:00Z");
    assert_eq!(json["environment"]["name"], "ref");
    assert_eq!(json["environment"]["detection"]["method"], "chain");
    assert_eq!(json["profile"]["name"], "smb-aut");
    let positions: Vec<&str> = json["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["position"].as_str().unwrap())
        .collect();
    assert_eq!(positions, ["end_entity", "sub_ca", "root"]);

    let text = stdout(&tir(&[
        "pki",
        "verify",
        &fixture("admission-1.pem"),
        "--issuer",
        &ca,
        "--at",
        "2026-06-01T00:00:00Z",
    ]));
    assert!(text.contains("| **result** | **VALID** |"), "{text}");
    assert!(text.contains("**not checked** (offline)"), "{text}");
}

#[test]
fn verify_without_the_issuer_is_incomplete_with_a_hint() {
    let (code, json) = verify_json(&["--env", "ref"]);
    assert_eq!(code, Some(1));
    assert_eq!(json["valid"], false);
    assert_eq!(json["environment"]["detection"], serde_json::Value::Null);
    assert_eq!(json["errors"][0]["code"], "chain_incomplete");
    let text = stdout(&tir(&[
        "pki",
        "verify",
        &fixture("admission-1.pem"),
        "--env",
        "ref",
    ]));
    assert!(
        text.contains("pass the issuing CA with `--issuer`"),
        "{text}"
    );
}

#[test]
fn verify_under_a_foreign_profile_misses_its_role() {
    let ca = fixture("smcb-ca51-test-only.pem");
    let (code, json) = verify_json(&[
        "--issuer",
        &ca,
        "--profile",
        "idp-sig",
        "--at",
        "2026-06-01T00:00:00Z",
    ]);
    assert_eq!(code, Some(1));
    assert_eq!(json["profile"]["reason"], "forced");
    let codes = |key: &str| -> Vec<String> {
        json[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["code"].as_str().unwrap().to_owned())
            .collect()
    };
    assert!(codes("errors").contains(&"role_oid_missing".to_owned()));
    assert_eq!(codes("warnings"), ["profile_type_mismatch"]);
}

#[test]
fn verify_after_the_end_entity_expired() {
    let ca = fixture("smcb-ca51-test-only.pem");
    let (code, json) = verify_json(&["--issuer", &ca, "--at", "2029-01-01T00:00:00Z"]);
    assert_eq!(code, Some(1));
    assert_eq!(json["errors"][0]["code"], "expired", "{json}");
}

#[test]
fn verify_usage_errors() {
    let ee = fixture("admission-1.pem");
    let bad_time = tir(&["pki", "verify", &ee, "--at", "yesterday"]);
    assert_eq!(bad_time.status.code(), Some(2));
    assert!(stderr(&bad_time).contains("RFC 3339"));
    let bad_profile = tir(&["pki", "verify", &ee, "--profile", "nope"]);
    assert_eq!(bad_profile.status.code(), Some(2));
    let pu = tir(&["pki", "verify", &ee, "--env", "pu"]);
    assert_eq!(pu.status.code(), Some(1), "pu is an alias of prod");
}

#[test]
fn verify_asks_for_the_environment_when_nothing_tells() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ti-pki/tests/pki/rogue-root.pem");
    let out = tir(&["--format", "json", "pki", "verify", root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "environment_undetected");
    assert_eq!(error["error"]["hint"], "pass --env prod, ref, test or dev");
}
