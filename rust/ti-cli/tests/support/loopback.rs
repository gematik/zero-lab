//! Fake TI services on 127.0.0.1 for the end-to-end tests: a one-request-per-connection
//! HTTP/1.1 server, and an IDP-Dienst on it that signs with ti-idpd's TEST-ONLY signer
//! and answers as gemSpec_IDP_Dienst describes.

#![allow(dead_code, reason = "each test file uses a part")]

use std::cell::RefCell;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwk::{EcKey, Jwk, KeyMaterial, Secret};
use jwz::jws;
use jwz::keys::{SoftwareAgreementKey, SoftwareKey};
use serde_json::json;

pub type Backend = jwz::crypto::Extended<RustCrypto>;

pub fn backend() -> Arc<Backend> {
    Arc::new(jwz_brainpool::backend(RustCrypto::new()))
}

fn manifest(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// One request as the server read it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    /// The target, query included.
    pub target: String,
    pub body: String,
}

impl Seen {
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap()
    }

    /// The query's `name`, percent-decoded.
    pub fn query(&self, name: &str) -> Option<String> {
        let (_, query) = self.target.split_once('?')?;
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(k, _)| *k == name)
            .map(|(_, v)| percent_decode(v))
    }
}

pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

pub fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => write!(out, "%{byte:02X}").unwrap(),
        }
    }
    out
}

/// An HTTP/1.1 response.
pub fn http(status: u16, content_type: &str, body: &[u8], location: Option<&str>) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        302 => "Found",
        401 => "Unauthorized",
        _ => "Not Found",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(location) = location {
        out.push_str("Location: ");
        out.push_str(location);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// A server on 127.0.0.1 answering with `handler` until dropped; `stop` returns what it
/// saw.
pub struct Server {
    pub base_url: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<Vec<Seen>>>,
}

impl Server {
    /// `make` gets the server's URL and returns the handler.
    pub fn start<H>(make: impl FnOnce(&str) -> H) -> Server
    where
        H: Fn(&Seen) -> Vec<u8> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let handler = make(&base_url);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut seen = Vec::new();
            listener.set_nonblocking(true).unwrap();
            while !stopping.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                let request = read_request(&stream);
                let response = handler(&request);
                seen.push(request);
                stream.write_all(&response).unwrap();
                let _ = stream.flush();
            }
            seen
        });
        Server {
            base_url,
            stop,
            thread: Some(thread),
        }
    }

    pub fn stop(mut self) -> Vec<Seen> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Method, target and body of one HTTP/1.1 request.
fn read_request(stream: &TcpStream) -> Seen {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some(value) = header
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.trim())
        {
            length = value.parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    Seen {
        method,
        target,
        body: String::from_utf8(body).unwrap(),
    }
}

/// ti-idpd's TEST-ONLY IDP signer under `kid`, and its certificate.
pub fn idp_signer(kid: &str) -> (SoftwareKey<Backend>, Vec<u8>) {
    let dir = manifest("../ti-idpd/tests/fixtures");
    let cert = ti_pki::parse_pem_certificates(&std::fs::read(dir.join("idpd-sig.pem")).unwrap())
        .unwrap()
        .remove(0);
    let pem = std::fs::read(dir.join("idpd-sig.key")).unwrap();
    let (_, der) = pem_rfc7468::decode_vec(&pem).unwrap();
    let scalar = sec1::EcPrivateKey::try_from(der.as_slice())
        .unwrap()
        .private_key
        .to_vec();
    let mut material = EcKey::from_point("BP-256", cert.public_key());
    material.d = Some(Secret::new(scalar));
    let key = SoftwareKey::from_jwk(
        &Jwk::new(KeyMaterial::Ec(material)),
        jwz_brainpool::BP256R1,
        &jwz_brainpool::registry(),
        backend(),
    )
    .unwrap()
    .with_kid(kid);
    (key, cert.der().to_vec())
}

/// What the fake IDP does when the challenge is answered.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Code,
    Refuse,
}

/// An IDP-Dienst on the loopback: discovery document, keys, challenge for any
/// authorization URL, and the code (or refusal) redirected to the authorization URL's
/// `redirect_uri` with its `state` — `https://rp.test/cb` when it names none.
pub struct FakeIdp {
    pub base_url: String,
    server: Option<Server>,
}

impl FakeIdp {
    pub fn start(answer: Answer) -> FakeIdp {
        let (disc_sig, disc_cert) = idp_signer("puk_disc_sig");
        let (idp_sig, idp_sig_cert) = idp_signer("puk_idp_sig");
        let mut idp_enc = SoftwareAgreementKey::generate(jwz_brainpool::BP_256, backend())
            .unwrap()
            .public_jwk();
        idp_enc.kid = Some("puk_idp_enc".into());
        // The challenge's relying party, remembered for the answer's redirect.
        let relying_party: RefCell<(String, Option<String>)> =
            RefCell::new(("https://rp.test/cb".to_owned(), None));
        let server = Server::start(|own| {
            let own = own.to_owned();
            move |request: &Seen| match (request.method.as_str(), request.path()) {
                ("GET", "/.well-known/openid-configuration") => {
                    let metadata = json!({
                        "issuer": own,
                        "authorization_endpoint": format!("{own}/sign_response"),
                        "token_endpoint": format!("{own}/token"),
                        "uri_puk_idp_sig": format!("{own}/idpSig/jwk.json"),
                        "uri_puk_idp_enc": format!("{own}/idpEnc/jwk.json"),
                        "iat": now() - 60, "exp": now() + 86_400,
                    });
                    let token = jws::sign(
                        metadata.to_string().as_bytes(),
                        HeaderParams::new().typ("JWT").x5c(&[&disc_cert]),
                        &disc_sig,
                    )
                    .unwrap();
                    http(200, "application/jwt", token.as_bytes(), None)
                }
                ("GET", "/idpSig/jwk.json") => {
                    use base64ct::{Base64, Encoding};
                    let mut jwk = idp_sig.public_jwk();
                    jwk.x5c = Some(vec![Base64::encode_string(&idp_sig_cert)]);
                    http(200, "application/json", jwk.to_json().as_bytes(), None)
                }
                ("GET", "/idpEnc/jwk.json") => {
                    http(200, "application/json", idp_enc.to_json().as_bytes(), None)
                }
                ("GET", "/sign_response") => {
                    let redirect_uri = request
                        .query("redirect_uri")
                        .unwrap_or_else(|| "https://rp.test/cb".to_owned());
                    let state = request.query("state");
                    *relying_party.borrow_mut() = (redirect_uri.clone(), state.clone());
                    let claims = json!({
                        "iss": own, "iat": now() - 1, "exp": now() + 180,
                        "token_type": "challenge", "jti": "j1", "snc": "snc",
                        "scope": request.query("scope").unwrap_or_else(|| "openid e-rezept".to_owned()),
                        "code_challenge": "c", "code_challenge_method": "S256",
                        "response_type": "code", "redirect_uri": redirect_uri,
                        "client_id": request.query("client_id").unwrap_or_else(|| "gematikTestPs".to_owned()),
                        "state": state, "nonce": "n1",
                    });
                    let challenge = jws::sign(
                        claims.to_string().as_bytes(),
                        HeaderParams::new().typ("JWT"),
                        &idp_sig,
                    )
                    .unwrap();
                    let body = json!({"challenge": challenge, "user_consent": {"requested_scopes": {}, "requested_claims": {}}});
                    http(200, "application/json", body.to_string().as_bytes(), None)
                }
                ("POST", "/sign_response") => {
                    let (redirect_uri, state) = relying_party.borrow().clone();
                    let state = state.map_or(String::new(), |s| format!("&state={s}"));
                    let location = match answer {
                        Answer::Code => format!("{redirect_uri}?code=CODE.from.idp{state}"),
                        Answer::Refuse => format!(
                            "{redirect_uri}?error=access_denied&gematik_error_text=Karte+unbekannt&gematik_code=2030&gematik_timestamp=1&gematik_uuid=u1{state}"
                        ),
                    };
                    http(302, "text/plain", b"", Some(&location))
                }
                other => http(404, "text/plain", format!("{other:?}").as_bytes(), None),
            }
        });
        FakeIdp {
            base_url: server.base_url.clone(),
            server: Some(server),
        }
    }

    /// The bodies posted to the authorization endpoint, in order.
    pub fn stop(mut self) -> Vec<String> {
        self.server
            .take()
            .unwrap()
            .stop()
            .into_iter()
            .filter(|r| r.method == "POST" && r.path() == "/sign_response")
            .map(|r| r.body)
            .collect()
    }
}
