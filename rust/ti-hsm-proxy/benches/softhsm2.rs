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

//! Throughput and latency of a token through a session pool, called directly and through
//! JSON-RPC 2.0 over a Unix socket, to tell what bounds a sidecar: the token, the sessions
//! or the transport.
//!
//! Gated like the spike suite: `just hsm-bench` sets `TI_HSM_PKCS11_MODULE_PATH` and a
//! fresh `SOFTHSM2_CONF`. `TI_HSM_BENCH_SECONDS` sets how long each row runs (default 2).
//!
//! The JSON-RPC rows multiplex every call over one connection: the client keeps as many
//! requests in flight as there are sessions, the server hands each line to a worker per
//! session and writes the answers in the order they finish, matched by their `id`. The
//! `ping` rows answer without the token and so measure the transport alone.

use std::collections::HashMap;
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::num::NonZeroUsize;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use base64ct::{Base64, Encoding as _};
use cryptoki::types::AuthPin;
use serde_json::{Value, json};
use ti_hsm_proxy::{Curve, Error, Iv, Module, Pool, SignInput, SigningKey, Token};

const TOKEN: &str = "ti-hsm-bench";
const WAIT: Duration = Duration::from_secs(10);

fn user_pin() -> AuthPin {
    AuthPin::from("user-pin-TEST-ONLY")
}

/// What one row measured.
struct Row {
    label: String,
    sessions: usize,
    callers: usize,
    elapsed: Duration,
    latencies: Vec<Duration>,
}

impl Row {
    fn print(&mut self) {
        self.latencies.sort_unstable();
        let ops = self.latencies.len();
        let per_second =
            u128::try_from(ops).unwrap_or(u128::MAX) * 1_000_000 / self.elapsed.as_micros().max(1);
        let at = |percent: usize| {
            self.latencies
                .get(ops * percent / 100)
                .or(self.latencies.last())
                .map_or(0, Duration::as_micros)
        };
        println!(
            "| {} | {} | {} | {} | {} | {} |",
            self.label,
            self.sessions,
            self.callers,
            per_second,
            at(50),
            at(99)
        );
    }
}

fn main() -> ExitCode {
    let Some(path) = std::env::var_os("TI_HSM_PKCS11_MODULE_PATH").map(PathBuf::from) else {
        eprintln!("needs TI_HSM_PKCS11_MODULE_PATH, the PKCS#11 module to measure: just hsm-bench");
        return ExitCode::FAILURE;
    };
    let seconds = std::env::var("TI_HSM_BENCH_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    match run(&path, Duration::from_secs(seconds)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum BenchError {
    #[error(transparent)]
    Hsm(#[from] Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Protocol(String),
}

fn run(path: &Path, duration: Duration) -> Result<(), BenchError> {
    let module = Module::load(path)?;
    module.provision(TOKEN, &AuthPin::from("so-pin-TEST-ONLY"), &user_pin())?;
    let cpus = thread::available_parallelism().map_or(1, NonZeroUsize::get);
    println!("{}, {cpus} CPUs, {duration:?} per row", module.describe()?);
    println!();
    println!("| operation | sessions | callers | ops/s | p50 µs | p99 µs |");
    println!("|---|---|---|---|---|---|");

    let mut sizes = vec![1, 2, 4, 8, cpus];
    sizes.sort_unstable();
    sizes.dedup();
    let digest = [0x5a; 32];
    let plaintext = [0xa5; 1024];

    for &n in &sizes {
        let pool = pool(&module, n)?;
        let key = pool.with(WAIT, |t| t.signing_key("bench-p256", Curve::P256))?;
        direct("ECDSA P-256, direct", &pool, n, duration, |_, t| {
            t.sign(&key, SignInput::Digest(&digest)).map(drop)
        })?
        .print();
    }
    {
        let pool = pool(&module, 1)?;
        let key = pool.with(WAIT, |t| t.signing_key("bench-p256", Curve::P256))?;
        direct("ECDSA P-256, direct", &pool, cpus, duration, |_, t| {
            t.sign(&key, SignInput::Digest(&digest)).map(drop)
        })?
        .print();
    }
    for &n in &sizes {
        let pool = pool(&module, n)?;
        let keys = (0..n)
            .map(|i| {
                pool.with(WAIT, |t| {
                    t.signing_key(&format!("bench-p256-{i}"), Curve::P256)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        direct(
            "ECDSA P-256, a key per caller",
            &pool,
            n,
            duration,
            |i, t| {
                let key = keys.get(i).ok_or(Error::Input("a key per caller"))?;
                t.sign(key, SignInput::Digest(&digest)).map(drop)
            },
        )?
        .print();
    }
    for &n in &sizes {
        let pool = pool(&module, n)?;
        let key = pool.with(WAIT, |t| t.signing_key("bench-p384", Curve::P384))?;
        let digest = [0x5a; 48];
        direct("ECDSA P-384, direct", &pool, n, duration, |_, t| {
            t.sign(&key, SignInput::Digest(&digest)).map(drop)
        })?
        .print();
    }
    for &n in &sizes {
        let pool = pool(&module, n)?;
        let key = pool.with(WAIT, |t| t.key_encryption_key("bench-aes"))?;
        direct("AES-256-GCM 1 KiB, direct", &pool, n, duration, |_, t| {
            t.encrypt(&key, &plaintext, b"aad", Iv::Random).map(drop)
        })?
        .print();
    }
    let socket = std::env::temp_dir().join(format!("ti-hsm-bench-{}.sock", std::process::id()));
    for method in ["sign", "ping"] {
        for &n in &sizes {
            let pool = pool(&module, n)?;
            let key = pool.with(WAIT, |t| t.signing_key("bench-p256", Curve::P256))?;
            let label = if method == "sign" {
                "ECDSA P-256, JSON-RPC"
            } else {
                "ping, JSON-RPC"
            };
            over_json_rpc(label, method, &socket, &pool, &key, n, duration)?.print();
        }
    }
    Ok(())
}

fn pool(module: &Module, size: usize) -> Result<Pool, BenchError> {
    let size = NonZeroUsize::new(size).ok_or(Error::Input("a pool has a session"))?;
    Ok(module.pool(TOKEN, &user_pin(), size)?)
}

/// `callers` threads run `operation` on the pool until `duration` has passed.
fn direct(
    label: &str,
    pool: &Pool,
    callers: usize,
    duration: Duration,
    operation: impl Fn(usize, &Token) -> Result<(), Error> + Sync,
) -> Result<Row, BenchError> {
    let start = Instant::now();
    let deadline = start + duration;
    let operation = &operation;
    let per_caller = thread::scope(|scope| {
        let handles: Vec<_> = (0..callers)
            .map(|caller| {
                scope.spawn(move || {
                    let mut latencies = Vec::new();
                    while Instant::now() < deadline {
                        let began = Instant::now();
                        pool.with(WAIT, |t| operation(caller, t))?;
                        latencies.push(began.elapsed());
                    }
                    Ok::<_, Error>(latencies)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or(Err(Error::Input("a caller panicked"))))
            .collect::<Result<Vec<_>, _>>()
    })?;
    Ok(Row {
        label: label.to_owned(),
        sessions: pool.size(),
        callers,
        elapsed: start.elapsed(),
        latencies: per_caller.into_iter().flatten().collect(),
    })
}

/// A JSON-RPC 2.0 server on `socket` with a worker per session, and a client that keeps
/// `in_flight` calls of `method` open on one connection until `duration` has passed.
fn over_json_rpc(
    label: &str,
    method: &str,
    socket: &Path,
    pool: &Pool,
    key: &SigningKey,
    in_flight: usize,
    duration: Duration,
) -> Result<Row, BenchError> {
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    let digest = Base64::encode_string(&[0x5a; 32]);
    let result = thread::scope(|scope| {
        let server = scope.spawn(|| serve(&listener, pool, key));
        let client = call(socket, method, &digest, in_flight, duration);
        let stopped = server
            .join()
            .unwrap_or_else(|_| Err(BenchError::Protocol("the server panicked".into())));
        let (elapsed, latencies) = client?;
        stopped?;
        Ok::<_, BenchError>(Row {
            label: label.to_owned(),
            sessions: pool.size(),
            callers: in_flight,
            elapsed,
            latencies,
        })
    });
    let _ = std::fs::remove_file(socket);
    result
}

fn serve(listener: &UnixListener, pool: &Pool, key: &SigningKey) -> Result<(), BenchError> {
    let (stream, _) = listener.accept()?;
    let writer = Mutex::new(stream.try_clone()?);
    let (queue, work) = mpsc::sync_channel::<String>(pool.size() * 2);
    let work = Mutex::new(work);
    thread::scope(|scope| {
        for _ in 0..pool.size() {
            scope.spawn(|| -> Result<(), BenchError> {
                loop {
                    let next = work.lock().unwrap_or_else(PoisonError::into_inner).recv();
                    let Ok(line) = next else { return Ok(()) };
                    let mut reply = answer(&line, pool, key).to_string();
                    reply.push('\n');
                    writer
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .write_all(reply.as_bytes())?;
                }
            });
        }
        for line in BufReader::new(stream).lines() {
            if queue.send(line?).is_err() {
                break;
            }
        }
        drop(queue);
        Ok(())
    })
}

fn answer(line: &str, pool: &Pool, key: &SigningKey) -> Value {
    let Ok(request) = serde_json::from_str::<Value>(line) else {
        return json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}});
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let outcome = match request.get("method").and_then(Value::as_str) {
        Some("ping") => Ok(json!({})),
        Some("sign") => request
            .pointer("/params/digest")
            .and_then(Value::as_str)
            .and_then(|d| Base64::decode_vec(d).ok())
            .ok_or_else(|| "params.digest is base64".to_owned())
            .and_then(|digest| {
                pool.with(WAIT, |t| t.sign(key, SignInput::Digest(&digest)))
                    .map(|s| json!({"signature": Base64::encode_string(&s)}))
                    .map_err(|e| e.to_string())
            }),
        _ => Err("no such method".to_owned()),
    };
    match outcome {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(message) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": message}})
        }
    }
}

fn call(
    socket: &Path,
    method: &str,
    digest: &str,
    in_flight: usize,
    duration: Duration,
) -> Result<(Duration, Vec<Duration>), BenchError> {
    let mut writer = UnixStream::connect(socket)?;
    let reader = BufReader::new(writer.try_clone()?);
    let sent = Mutex::new(HashMap::<u64, Instant>::new());
    // A unit per call in flight: sending blocks once `in_flight` are open, each answer
    // frees one.
    let (open, answered) = mpsc::sync_channel::<()>(in_flight);
    let failures = AtomicU64::new(0);
    let start = Instant::now();
    let deadline = start + duration;
    let (sent, failures) = (&sent, &failures);
    let latencies = thread::scope(|scope| {
        let receiver = scope.spawn(move || -> Result<Vec<Duration>, BenchError> {
            let mut latencies = Vec::new();
            for line in reader.lines() {
                let reply: Value = serde_json::from_str(&line?)
                    .map_err(|e| BenchError::Protocol(format!("an answer is not JSON: {e}")))?;
                if reply.get("result").is_none() {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
                let id = reply.get("id").and_then(Value::as_u64);
                let began = id.and_then(|id| {
                    sent.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&id)
                });
                let began =
                    began.ok_or_else(|| BenchError::Protocol("an answer to no call".into()))?;
                latencies.push(began.elapsed());
                if answered.recv().is_err() {
                    break;
                }
            }
            Ok(latencies)
        });
        let mut id = 0u64;
        while Instant::now() < deadline {
            id += 1;
            if open.send(()).is_err() {
                break;
            }
            let request = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{{\"key\":\"bench-p256\",\"digest\":\"{digest}\"}}}}\n"
            );
            sent.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id, Instant::now());
            writer.write_all(request.as_bytes())?;
        }
        // Once `in_flight` more units fit, every call has been answered.
        for _ in 0..in_flight {
            if open.send(()).is_err() {
                break;
            }
        }
        writer.shutdown(std::net::Shutdown::Both)?;
        receiver
            .join()
            .unwrap_or_else(|_| Err(BenchError::Protocol("the client panicked".into())))
    })?;
    let elapsed = start.elapsed();
    match failures.load(Ordering::Relaxed) {
        0 => Ok((elapsed, latencies)),
        n => Err(BenchError::Protocol(format!("{n} calls failed"))),
    }
}
