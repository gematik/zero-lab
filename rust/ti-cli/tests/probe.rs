/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 */

//! `ti probe` against a local fake of the TI services (plain HTTP, endpoints from
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
    let dir = std::env::temp_dir().join(format!("ti-probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let endpoints = dir.join("endpoints.json");
    std::fs::write(
        &endpoints,
        format!(
            r#"{{"dev": [
                {{"name": "idpd-ti", "access": "ti-vpn", "kind": "oidc", "url": "{base}"}},
                {{"name": "erx", "access": "ti-vpn", "kind": "erp", "url": "{base}"}},
                {{"name": "stall", "access": "internet", "kind": "http", "url": "{base}/stall"}},
                {{"name": "popp", "access": "internet", "kind": "zeta", "url": "{base}"}},
                {{"name": "catalog", "access": "internet", "kind": "catalog", "url": "{base}/catalog.json"}}
            ]}}"#
        ),
    )
    .unwrap();

    let start = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_ti"))
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
    assert_eq!(probe("idpd-ti")["detail"], "oidc discovery");
    assert_eq!(probe("erx")["detail"], "erp VAU certificate");
    assert_eq!(probe("popp")["detail"], "zeta resource metadata");
    assert_eq!(
        (
            probe("stall")["status"].as_str(),
            probe("stall")["detail"].as_str()
        ),
        (Some("fail"), Some("timeout"))
    );
    let vsdm = probe("vsdm-9");
    assert_eq!(
        (
            vsdm["source"].as_str(),
            vsdm["status"].as_str(),
            vsdm["access"].as_str()
        ),
        (Some("catalog"), Some("ok"), Some("internet"))
    );
    assert_eq!(probe("erx")["access"], "ti-vpn");
    assert_eq!(
        report["access_paths"],
        serde_json::json!([
            {"access": "ti-vpn", "available": true, "probes": 2},
            {"access": "internet", "available": true, "probes": 4},
        ])
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

/// Without the TI VPN none of its endpoints answers: the block says so once and is gray
/// in the text, and the JSON marks the path unavailable; the internet block is unaffected.
#[test]
fn a_missing_ti_vpn_grays_out_its_block() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let server_base = base.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let base = server_base.clone();
            std::thread::spawn(move || serve(stream, &base));
        }
    });
    // A port nothing listens on: refused at once, as a VPN-only host without the VPN.
    let closed = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://127.0.0.1:{}", probe.local_addr().unwrap().port())
    };
    let dir = std::env::temp_dir().join(format!("ti-probe-vpn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let endpoints = dir.join("endpoints.json");
    std::fs::write(
        &endpoints,
        format!(
            r#"{{"dev": [
                {{"name": "idpd-ti", "access": "ti-vpn", "kind": "oidc", "url": "{closed}"}},
                {{"name": "erx", "access": "ti-vpn", "kind": "erp", "url": "{closed}"}},
                {{"name": "popp", "access": "internet", "kind": "zeta", "url": "{base}"}}
            ]}}"#
        ),
    )
    .unwrap();
    let run = |format: &str| {
        Command::new(env!("CARGO_BIN_EXE_ti"))
            .args(["--format", format, "probe", "dev"])
            .env("TI_PROBE_ENDPOINTS_PATH", &endpoints)
            .env("NO_COLOR", "1")
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .output()
            .unwrap()
    };
    let json = run("json");
    let text = String::from_utf8(run("text").stdout).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_conforms("probe", &json.stdout);
    let report: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        report["access_paths"],
        serde_json::json!([
            {"access": "ti-vpn", "available": false, "probes": 2},
            {"access": "internet", "available": true, "probes": 1},
        ])
    );
    assert!(
        text.contains("\nTI-VPN · not reachable: no TI VPN?\n"),
        "{text}"
    );
    assert!(
        text.contains("\n  erx "),
        "rows indented under their path: {text}"
    );
    assert!(text.contains("\nInternet\n"), "{text}");
    let vpn = text.find("TI-VPN").unwrap();
    let internet = text.find("\nInternet\n").unwrap();
    assert!(vpn < internet, "TI-VPN first: {text}");
    assert!(text[vpn..internet].contains("erx"), "{text}");
    assert!(text[internet..].contains("popp"), "{text}");
    assert!(
        text.contains("· TI-VPN not reachable"),
        "the summary says it: {text}"
    );
}

/// HITL: the built-in endpoints of a real environment, run once with the TI VPN of a
/// Konnektor or TI-Gateway up and once without. The TI-VPN block answers exactly when
/// the VPN is up; the internet block answers either way.
#[test]
#[ignore = "HITL, needs TI_TEST_PROBE_ENV and TI_TEST_PROBE_VPN=on|off"]
fn hitl_the_ti_vpn_block_answers_exactly_with_the_vpn() {
    let env =
        std::env::var("TI_TEST_PROBE_ENV").expect("TI_TEST_PROBE_ENV: prod, ref, test or dev");
    let vpn = match std::env::var("TI_TEST_PROBE_VPN").as_deref() {
        Ok("on") => true,
        Ok("off") => false,
        other => panic!("TI_TEST_PROBE_VPN: on or off, not {other:?}"),
    };
    let out = Command::new(env!("CARGO_BIN_EXE_ti"))
        .args(["--format", "json", "probe", &env])
        .env_remove("TI_PROBE_ENDPOINTS_PATH")
        .output()
        .unwrap();
    assert_conforms("probe", &out.stdout);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&report["access_paths"]).unwrap()
    );
    let available = |access: &str| {
        report["access_paths"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["access"] == access)
            .unwrap_or_else(|| panic!("{access} in {report}"))["available"]
            .as_bool()
            .unwrap()
    };
    assert_eq!(
        available("ti-vpn"),
        vpn,
        "TI VPN {}: {report}",
        if vpn { "on" } else { "off" }
    );
    assert!(available("internet"), "{report}");
}
