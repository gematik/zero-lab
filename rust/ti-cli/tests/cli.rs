//! The `ti` binary as a user or an agent sees it: arguments, stdout, stderr, exit codes.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn ti(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ti"))
        .args(args)
        .env_remove("TI_FORMAT")
        .env_remove("TI_ENV")
        // Nothing cached: --offline runs see the embedded roots only, whatever an
        // earlier run on this machine downloaded.
        .env(
            "TI_CACHE_DIR",
            std::env::temp_dir().join("ti-tests-no-cache"),
        )
        // The TSL state of an earlier list must not reject the fixtures, nor may the
        // tests leave one in the user's state directory.
        .env(
            "XDG_STATE_HOME",
            std::env::temp_dir().join("ti-tests-state"),
        )
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR_FORCE")
        .output()
        .unwrap()
}

fn ti_with_stdin(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ti"))
        .args(args)
        .env(
            "XDG_STATE_HOME",
            std::env::temp_dir().join("ti-tests-state"),
        )
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
    let markdown = stdout(&ti(&["pki", "inspect", &file]));
    assert!(
        markdown.starts_with("**Arztpraxis Bernd Rosenstrauch TEST-ONLY** · `C.HCI.AUT`"),
        "{markdown}"
    );
    assert!(markdown.contains("\n- key: "), "{markdown}");
    assert!(
        markdown.contains("```pem\n-----BEGIN CERTIFICATE-----\n"),
        "{markdown}"
    );
    assert!(!markdown.contains("| "), "no tables: {markdown}");

    let text = stdout(&ti(&["--format", "text", "pki", "inspect", &file]));
    assert!(
        text.starts_with("Subject\n"),
        "sections on a terminal: {text}"
    );
    assert!(text.contains("\n  type           C.HCI.AUT\n"), "{text}");
    assert!(
        !text.contains("BEGIN CERTIFICATE"),
        "no PEM on a terminal: {text}"
    );
}

#[test]
fn timestamps_in_the_system_zone() {
    let out = Command::new(env!("CARGO_BIN_EXE_ti"))
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
    assert!(text.contains("2023-11-10 00:00 CET"), "{text}");
}

#[test]
fn inspect_prints_plain_text_when_piped() {
    let out = ti(&["pki", "inspect", &fixture("admission-1.pem")]);
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
    let forced = ti(&[
        "--format", "text", "--color", "always", "pki", "inspect", &file,
    ]);
    assert!(stdout(&forced).contains('\x1b'));
    let never = Command::new(env!("CARGO_BIN_EXE_ti"))
        .args(["--format", "text", "pki", "inspect", &file])
        .env("CLICOLOR_FORCE", "1")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(!stdout(&never).contains('\x1b'), "NO_COLOR wins");
}

#[test]
fn inspect_json_is_the_contract() {
    let out = ti(&[
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
    let out = Command::new(env!("CARGO_BIN_EXE_ti"))
        .args(["pki", "profiles", "list"])
        .env("TI_FORMAT", "json")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        json["profiles"].as_array().unwrap().len(),
        ti_pki::profile::PROFILES.len()
    );
}

#[test]
fn stdin_pem_and_der() {
    let pem = std::fs::read(fixture("admission-1.pem")).unwrap();
    let from_pem = ti_with_stdin(&["pki", "inspect", "-"], &pem);
    assert_eq!(from_pem.status.code(), Some(0), "{}", stderr(&from_pem));
    assert!(stdout(&from_pem).contains("Arztpraxis Bernd Rosenstrauch"));
    let json = ti_with_stdin(&["--format", "json", "pki", "inspect", "-"], &pem);
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json["source"], "<stdin>");

    let der = ti_pki::parse_pem_certificates(&pem).unwrap()[0]
        .der()
        .to_vec();
    let from_der = ti_with_stdin(&["--format", "json", "pki", "inspect", "-"], &der);
    let json: serde_json::Value = serde_json::from_slice(&from_der.stdout).unwrap();
    assert_eq!(json["certificates"][0]["certificate_type"], "C.HCI.AUT");
}

#[test]
fn unreadable_input_is_exit_4_with_a_hint() {
    let out = ti(&["pki", "inspect", "/nonexistent/card.pem"]);
    assert_eq!(out.status.code(), Some(4));
    assert!(stdout(&out).is_empty());
    let err = stderr(&out);
    assert!(err.contains("cannot read /nonexistent/card.pem"), "{err}");
    assert!(err.contains("hint:"), "{err}");

    let json = ti(&[
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

    let empty = ti_with_stdin(&["pki", "inspect", "-"], b"");
    assert_eq!(empty.status.code(), Some(4));
    assert!(stderr(&empty).contains("no certificate found"));
}

#[test]
fn profiles() {
    let list = stdout(&ti(&["pki", "profiles", "list"]));
    for name in [
        "epa-vau-aut",
        "fd-tls-s",
        "idp-sig",
        "smb-aut",
        "zeta-guard-aut",
    ] {
        assert!(list.contains(name), "{list}");
    }
    let describe = ti(&[
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

    let unknown = ti(&["pki", "profiles", "describe", "idp"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(
        stderr(&unknown).contains("smb-aut"),
        "lists the valid values"
    );
}

#[test]
fn http_options_are_validated_and_shown_with_verbose() {
    let dir = std::env::temp_dir().join("ti-cli-test-cache");
    let out = Command::new(env!("CARGO_BIN_EXE_ti"))
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
        assert_eq!(ti(&args).status.code(), Some(2), "{bad:?}");
    }
}

#[test]
fn help_documents_exit_codes() {
    let help = ti(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    let text = stdout(&help);
    assert!(text.contains("Exit codes:"), "{text}");
    assert!(text.contains("HTTP options"), "{text}");
}

/// `ti … | head` must end quietly: a closed stdout is not an error.
#[test]
fn a_closed_pipe_is_not_an_error() {
    let pem = std::fs::read(fixture("admission-1.pem")).unwrap();
    // Enough certificates to overflow any pipe buffer.
    let many: Vec<u8> = std::iter::repeat_n(pem.as_slice(), 400)
        .flatten()
        .copied()
        .collect();
    let dir = std::env::temp_dir().join(format!("ti-pipe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("many.pem");
    std::fs::write(&file, &many).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_ti"))
        .args(["pki", "inspect"])
        .arg(&file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = [0u8; 16];
    child.stdout.take().unwrap().read_exact(&mut first).unwrap();
    // Dropping the read end closes the pipe while ti is still writing.
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
    let mut args = vec![
        "--format",
        "json",
        "pki",
        "verify",
        "--offline",
        ee.as_str(),
    ];
    args.extend_from_slice(extra);
    let out = ti(&args);
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

    let text = stdout(&ti(&[
        "pki",
        "verify",
        "--offline",
        &fixture("admission-1.pem"),
        "--issuer",
        &ca,
        "--at",
        "2026-06-01T00:00:00Z",
    ]));
    assert!(text.starts_with("**VALID** · **Arztpraxis"), "{text}");
    assert!(
        text.contains("revocation **not checked** (offline)"),
        "{text}"
    );
    assert_eq!(
        text.matches("-----BEGIN CERTIFICATE-----").count(),
        3,
        "the chain"
    );
}

#[test]
fn verify_without_the_issuer_is_incomplete_with_a_hint() {
    let (code, json) = verify_json(&["--env", "ref"]);
    assert_eq!(code, Some(1));
    assert_eq!(json["valid"], false);
    assert_eq!(json["environment"]["detection"], serde_json::Value::Null);
    assert_eq!(json["errors"][0]["code"], "chain_incomplete");
    let text = stdout(&ti(&[
        "pki",
        "verify",
        "--offline",
        &fixture("admission-1.pem"),
        "--env",
        "ref",
    ]));
    assert!(text.contains("pass it with `--issuer`"), "{text}");
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
    let bad_time = ti(&["pki", "verify", "--offline", &ee, "--at", "yesterday"]);
    assert_eq!(bad_time.status.code(), Some(2));
    assert!(stderr(&bad_time).contains("RFC 3339"));
    let bad_profile = ti(&["pki", "verify", "--offline", &ee, "--profile", "nope"]);
    assert_eq!(bad_profile.status.code(), Some(2));
    let pu = ti(&["pki", "verify", "--offline", &ee, "--env", "pu"]);
    assert_eq!(pu.status.code(), Some(1), "pu is an alias of prod");
}

#[test]
fn verify_asks_for_the_environment_when_nothing_tells() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ti-pki/tests/pki/rogue-root.pem");
    let out = ti(&[
        "--format",
        "json",
        "pki",
        "verify",
        "--offline",
        root.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "environment_undetected");
    assert_eq!(error["error"]["hint"], "pass --env prod, ref, test or dev");
}

#[test]
fn verify_offline_without_a_cache_says_what_it_used() {
    let ca = fixture("smcb-ca51-test-only.pem");
    let (_, json) = verify_json(&["--issuer", &ca, "--at", "2026-06-01T00:00:00Z"]);
    assert_eq!(json["trust"]["source"], "embedded");
    assert_eq!(json["trust"]["intermediates"], 0);
    assert!(
        json["trust"]["note"]
            .as_str()
            .unwrap()
            .contains("nothing cached")
    );
    assert_eq!(json["revocation_mode"], "disabled");
    assert_eq!(json["insecure_transport"], false);
    assert_eq!(json["chain"][0]["revocation"], serde_json::Value::Null);
}

#[test]
fn unusable_http_options_are_usage_errors() {
    let ee = fixture("admission-1.pem");
    let out = ti(&[
        "--format",
        "json",
        "--cacert",
        "/nonexistent/ca.pem",
        "pki",
        "verify",
        &ee,
    ]);
    assert_eq!(out.status.code(), Some(2));
    let error: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "http_setup");
}

/// `probe ENV` and `--env` (and `TI_ENV`) name the same thing; these all fail before a
/// request is made.
#[test]
fn probe_takes_the_environment_as_argument_or_option() {
    let probe = |args: &[&str], ti_env: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ti"));
        command
            .args(["--format", "json", "probe"])
            .args(args)
            .env_remove("TI_ENV");
        if let Some(value) = ti_env {
            command.env("TI_ENV", value);
        }
        let out = command.output().unwrap();
        (out.status.code(), stderr(&out))
    };
    for (args, ti_env, says) in [
        (&[][..], None, "probe needs an environment"),
        (&[], Some("auto"), "probe needs an environment"),
        (&["--env", "auto"], None, "auto has nothing to detect"),
        (
            &["ref", "--env", "test"],
            None,
            "ENV ref and --env test disagree",
        ),
    ] {
        let (code, err) = probe(args, ti_env);
        assert_eq!(code, Some(2), "{args:?} {ti_env:?}: {err}");
        assert!(err.contains(says), "{args:?} {ti_env:?}: {err}");
        assert!(err.contains("environment_invalid"), "{err}");
    }
}

#[test]
fn completions_for_every_shell() {
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let out = ti(&["completions", shell]);
        assert_eq!(out.status.code(), Some(0), "{shell}");
        let script = stdout(&out);
        assert!(script.contains(ti_cli::BIN), "{shell} names the executable");
        assert!(script.contains("verify"), "{shell} knows the subcommands");
    }
    assert_eq!(ti(&["completions", "tcsh"]).status.code(), Some(2));
}

fn p12_fixture() -> (String, String) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ti-pkcs12/tests/fixtures/legacy");
    let password = std::fs::read_to_string(dir.join("cgm-password.txt")).unwrap();
    (
        dir.join("cgm.p12").to_string_lossy().into_owned(),
        password.trim().to_owned(),
    )
}

#[test]
fn inspect_reads_pkcs12_with_its_key_first() {
    let (file, password) = p12_fixture();
    let out = ti(&[
        "--format",
        "json",
        "pki",
        "inspect",
        &file,
        "--p12-password",
        &password,
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let certificates = json["certificates"].as_array().unwrap();
    assert_eq!(certificates.len(), 2);
    assert_eq!(certificates[0]["subject"], "CN=test-cs2");
    assert_eq!(certificates[0]["private_key"], true);
    assert_eq!(certificates[1]["private_key"], false);
    let text = stdout(&ti(&[
        "--format",
        "text",
        "pki",
        "inspect",
        &file,
        "--p12-password",
        &password,
    ]));
    assert!(text.contains("private key    in this file"), "{text}");
}

#[test]
fn a_wrong_p12_password_is_an_input_error_with_a_hint() {
    let (file, _) = p12_fixture();
    // The default password 00 is not this vendor file's.
    let out = ti(&["--format", "json", "pki", "inspect", &file]);
    assert_eq!(out.status.code(), Some(4));
    let error: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "p12_password");
    assert!(
        error["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("--p12-password")
    );
}

#[test]
fn verify_takes_the_certificate_with_its_key_as_end_entity() {
    let (file, password) = p12_fixture();
    let out = ti(&[
        "--format",
        "json",
        "pki",
        "verify",
        "--offline",
        "--env",
        "ref",
        &file,
        "--p12-password",
        &password,
    ]);
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["chain"][0]["common_name"], "test-cs2", "{json}");
}

#[test]
fn inspect_shows_the_pkcs12_container() {
    let (file, password) = p12_fixture();
    let out = ti(&[
        "--format",
        "json",
        "pki",
        "inspect",
        &file,
        "--p12-password",
        &password,
    ]);
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let p12 = &json["pkcs12"];
    assert_eq!(p12["encoding"], "BER");
    assert_eq!(p12["mac"]["iterations"], 102_400);
    assert_eq!(p12["keys"][0]["curve"], "brainpoolP256r1");
    assert_eq!(p12["keys"][0]["certificate"], 0);
    assert_eq!(json["certificates"][0]["friendly_name"], "test-cs2");
    let pem = ti(&[
        "--format",
        "json",
        "pki",
        "inspect",
        &fixture("admission-1.pem"),
    ]);
    let pem: serde_json::Value = serde_json::from_slice(&pem.stdout).unwrap();
    assert_eq!(pem["pkcs12"], serde_json::Value::Null);
}

#[test]
fn convert_writes_a_modern_private_file_and_keeps_existing_ones() {
    let (file, password) = p12_fixture();
    let dir = std::env::temp_dir().join(format!("ti-convert-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("modern.p12");
    let target = target.to_str().unwrap();
    let args = [
        "--format",
        "json",
        "pki",
        "pkcs12",
        "convert",
        &file,
        target,
        "--p12-password",
        &password,
    ];
    let out = ti(&args);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["before"]["encoding"], "BER");
    assert_eq!(report["after"]["mac"], "SHA-256 × 2048");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // The converted file reads like the original, now as DER.
    let inspected = ti(&[
        "--format",
        "json",
        "pki",
        "inspect",
        target,
        "--p12-password",
        &password,
    ]);
    let inspected: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(inspected["pkcs12"]["encoding"], "DER");
    assert_eq!(inspected["certificates"][0]["friendly_name"], "test-cs2");

    let again = ti(&args);
    assert_eq!(again.status.code(), Some(2), "no overwrite without --force");
    let mut forced = args.to_vec();
    forced.push("--force");
    assert_eq!(ti(&forced).status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}
