//! `tir probe` against a local fake of the TI services (plain HTTP, endpoints from
//! `TI_PROBE_ENDPOINTS_PATH`): the protocol checks, the catalog's instances, a
//! timeout, the JSON contract and the exit code.

mod support;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;

use support::assert_conforms;

const EE_ARZT: &str = include_str!("../../ti-pki/tests/pki/ee-arzt.pem");

fn serve(stream: TcpStream, base: &str) -> Option<()> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut request = String::new();
    reader.read_line(&mut request).ok()?;
    let path = request.split_whitespace().nth(1)?.to_owned();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        if line.trim_end().is_empty() {
            break;
        }
    }
    let der: Vec<u8> = pem_rfc7468::decode_vec(EE_ARZT.as_bytes()).ok()?.1;
    let (status, body): (u16, Vec<u8>) = match path.as_str() {
        "/.well-known/openid-configuration" => {
            (200, format!(r#"{{"issuer":"{base}"}}"#).into_bytes())
        }
        "/.well-known/oauth-protected-resource" | "/vsdm/.well-known/oauth-protected-resource" => (
            200,
            format!(r#"{{"resource":"{base}","authorization_servers":["{base}/as"]}}"#)
                .into_bytes(),
        ),
        "/catalog.json" => (
            200,
            format!(
                r#"{{"format_version":"0.9.2","env":"dev","service_instances":{{
                "popp-1":{{"type":"popp","url":"{base}"}},
                "vsdm-9":{{"type":"vsdm","url":"{base}/vsdm"}}}}}}"#
            )
            .into_bytes(),
        ),
        "/VAUCertificate" => (200, der),
        "/stall" => {
            std::thread::sleep(Duration::from_secs(5));
            (200, Vec::new())
        }
        _ => (404, Vec::new()),
    };
    let mut stream = stream;
    write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .ok()?;
    stream.write_all(&body).ok()
}

#[test]
fn probes_protocols_catalog_instances_and_timeouts() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let server_base = base.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let base = server_base.clone();
            std::thread::spawn(move || serve(stream, &base));
        }
    });
    let dir = std::env::temp_dir().join(format!("tir-probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let endpoints = dir.join("endpoints.json");
    std::fs::write(
        &endpoints,
        format!(
            r#"{{"dev": [
                {{"name": "IDP", "kind": "oidc", "url": "{base}"}},
                {{"name": "eRX", "kind": "erp", "url": "{base}"}},
                {{"name": "Stall", "kind": "http", "url": "{base}/stall"}},
                {{"name": "PoPP", "kind": "zeta", "url": "{base}"}},
                {{"name": "Catalog", "kind": "catalog", "url": "{base}/catalog.json"}}
            ]}}"#
        ),
    )
    .unwrap();

    let start = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_tir"))
        .args(["--format", "json", "probe", "dev"])
        .env("TI_PROBE_ENDPOINTS_PATH", &endpoints)
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .output()
        .unwrap();
    let elapsed = start.elapsed();
    let _ = std::fs::remove_dir_all(&dir);

    assert_conforms("probe", &out.stdout);
    assert_eq!(out.status.code(), Some(1), "one probe failed");
    assert!(
        elapsed < Duration::from_millis(4500),
        "3 s per request: {elapsed:?}"
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let probe = |name: &str| {
        report["probes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == name)
            .unwrap_or_else(|| panic!("{name} in {report}"))
            .clone()
    };
    assert_eq!(probe("IDP")["detail"], "oidc discovery");
    assert_eq!(probe("eRX")["detail"], "erp VAU certificate");
    assert_eq!(probe("PoPP")["detail"], "zeta resource metadata");
    assert_eq!(
        (
            probe("Stall")["status"].as_str(),
            probe("Stall")["detail"].as_str()
        ),
        (Some("fail"), Some("timeout"))
    );
    let vsdm = probe("vsdm-9");
    assert_eq!(
        (vsdm["source"].as_str(), vsdm["status"].as_str()),
        (Some("catalog"), Some("ok"))
    );
    assert_eq!(
        report["probes"].as_array().unwrap().len(),
        6,
        "popp-1 is the built-in PoPP"
    );
    assert_eq!(
        report["counts"],
        serde_json::json!({"ok": 5, "warn": 0, "fail": 1})
    );
}
