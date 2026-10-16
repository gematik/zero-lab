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

//! Answers the cases of spec/store/testdata/manifest.json with ti-store, for the corpus
//! tests and the conformance adapter (`examples/conformance.rs`).

use futures_lite::future::block_on;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ti_store::store::files::{FilesMeta, encode_record, parse_record};
use ti_store::store::profile::{Inputs, Platform, resolve};
use ti_store::store::{
    Backend, BatchOp, DataKey, Field, FixedRandom, KeyFileWrapper, KeyWrapper, Keyring,
    KeyringFile, Kid, Name, Namespace, Query, StoreError, StoredRecord, Tag, WrappedKey, derive,
    levels, open_plain, open_sealed, parse_kek_file, plain_name, plain_record, plain_tag,
    seal_record,
};
use ti_types::Timestamp;

/// A result: the code, and for `ok` the output.
pub type Answer = (String, Value);

/// The corpus could not be read as its kind says: a broken case, not a verdict.
#[derive(Debug)]
pub struct BadCase(pub String);

type R<T> = Result<T, Outcome>;

/// Why evaluation stopped: a result code of the implementation, or a broken case.
#[derive(Debug)]
pub enum Outcome {
    Code(StoreError),
    Bad(BadCase),
    Unsupported,
}

impl From<StoreError> for Outcome {
    fn from(e: StoreError) -> Self {
        Outcome::Code(e)
    }
}

fn bad(what: &str) -> Outcome {
    Outcome::Bad(BadCase(what.to_owned()))
}

pub fn hex(b: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

struct In<'a>(&'a Map<String, Value>);

impl In<'_> {
    fn has(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
    fn str(&self, k: &str) -> R<&str> {
        self.0.get(k).and_then(Value::as_str).ok_or_else(|| bad(k))
    }
    fn bytes(&self, k: &str) -> R<Vec<u8>> {
        unhex(self.str(k)?).ok_or_else(|| bad(k))
    }
    fn arr<const N: usize>(&self, k: &str) -> R<[u8; N]> {
        self.bytes(k)?.try_into().map_err(|_| bad(k))
    }
    fn num(&self, k: &str) -> R<u64> {
        self.0.get(k).and_then(Value::as_u64).ok_or_else(|| bad(k))
    }
    fn time(&self, k: &str) -> R<Option<Timestamp>> {
        Ok(Some(self.num(k)?).filter(|t| *t != 0).map(Timestamp))
    }
    fn list(&self, k: &str) -> R<Vec<&Map<String, Value>>> {
        match self.0.get(k) {
            None => Ok(Vec::new()),
            Some(Value::Array(a)) => a
                .iter()
                .map(|v| v.as_object().ok_or_else(|| bad(k)))
                .collect(),
            Some(_) => Err(bad(k)),
        }
    }
    fn tags(&self, k: &str) -> R<Vec<Tag>> {
        self.list(k)?
            .into_iter()
            .map(|t| {
                let t = In(t);
                Ok(Tag {
                    field: Field::new(t.str("field")?)?,
                    tag: t
                        .bytes("tag")?
                        .try_into()
                        .map_err(|_| StoreError::InvalidArgument("tag"))?,
                })
            })
            .collect()
    }
}

fn data_key(bytes: &[u8]) -> R<DataKey> {
    Ok(DataKey::from_bytes(
        bytes.try_into().map_err(|_| bad("data key"))?,
    ))
}

fn t(v: Option<Timestamp>) -> u64 {
    v.map_or(0, |t| t.0)
}

fn tags_out(tags: &[Tag]) -> Value {
    Value::Array(
        tags.iter()
            .map(|t| json!({"field": t.field.as_str(), "tag": hex(&t.tag)}))
            .collect(),
    )
}

/// The scenarios' backends; `None` answers `unsupported`.
pub trait Backends {
    type B: Backend;
    fn fresh(&self, name: &str) -> Option<Self::B>;
}

/// Evaluates one case. `Err` is a broken case.
pub fn evaluate<S: Backends>(kind: &str, input: &Value, backends: &S) -> Result<Answer, BadCase> {
    let Some(map) = input.as_object() else {
        return Err(BadCase("input is not an object".into()));
    };
    match answer(kind, &In(map), backends) {
        Ok(out) => Ok(("ok".into(), out)),
        Err(Outcome::Code(e)) => Ok((e.code().into(), Value::Null)),
        Err(Outcome::Unsupported) => Ok(("unsupported".into(), Value::Null)),
        Err(Outcome::Bad(b)) => Err(b),
    }
}

#[allow(clippy::too_many_lines, reason = "one arm per kind of the corpus")]
fn answer<S: Backends>(case_kind: &str, i: &In<'_>, backends: &S) -> R<Value> {
    Ok(match case_kind {
        "derive" => {
            let keys = derive(&data_key(&i.bytes("dk")?)?);
            let (v, n, x) = keys.expose();
            json!({"k_value": hex(v), "k_name": hex(n), "k_index": hex(x)})
        }
        "name" => {
            let ns = Namespace::new(i.str("ns")?)?;
            let id = i.bytes("id")?;
            let name = if i.has("dk") {
                derive(&data_key(&i.bytes("dk")?)?).name(&ns, &id)?
            } else {
                plain_name(&ns, &id)?
            };
            json!({"name": hex(&name.0)})
        }
        "tag" => {
            let ns = Namespace::new(i.str("ns")?)?;
            let field = Field::new(i.str("field")?)?;
            let value = i.bytes("value")?;
            let tag = if i.has("dk") {
                derive(&data_key(&i.bytes("dk")?)?).tag(&ns, &field, &value)?
            } else {
                plain_tag(&ns, &field, &value)?
            };
            json!({"tag": hex(&tag.tag)})
        }
        "seal" => {
            let keys = derive(&data_key(&i.bytes("dk")?)?);
            let ns = Namespace::new(i.str("ns")?)?;
            let id = i.bytes("id")?;
            let name = if i.has("index_dk") {
                derive(&data_key(&i.bytes("index_dk")?)?).name(&ns, &id)?
            } else {
                keys.name(&ns, &id)?
            };
            let kid = Kid::new(i.str("kid")?)?;
            let record = seal_record(
                keys.value_key(),
                &i.arr("profile_id")?,
                &kid,
                &ns,
                &name,
                i.time("not_after")?,
                &i.arr("nonce")?,
                &i.bytes("payload")?,
            )?;
            json!({"name": hex(&name.0), "record": hex(&record)})
        }
        "open" => {
            let mut ring = Vec::new();
            for (kid, v) in
                i.0.get("keys")
                    .and_then(Value::as_object)
                    .ok_or_else(|| bad("keys"))?
            {
                let bytes =
                    unhex(v.as_str().ok_or_else(|| bad("keys"))?).ok_or_else(|| bad("keys"))?;
                ring.push((Kid::new(kid)?, derive(&data_key(&bytes)?)));
            }
            let ns = Namespace::new(i.str("ns")?)?;
            let name = derive(&data_key(&i.bytes("index_dk")?)?).name(&ns, &i.bytes("id")?)?;
            let opened = open_sealed(
                |kid| {
                    ring.iter()
                        .find(|(k, _)| k == kid)
                        .map(|(_, keys)| keys.value_key())
                },
                &i.arr("profile_id")?,
                &ns,
                &name,
                Timestamp(i.num("now")?),
                &i.bytes("record")?,
            )?;
            json!({"kid": opened.kid.map(|k| k.as_str().to_owned()), "not_after": t(opened.not_after), "payload": hex(&opened.payload)})
        }
        "plain" => {
            let ns = Namespace::new(i.str("ns")?)?;
            let name = plain_name(&ns, &i.bytes("id")?)?;
            let record = plain_record(i.time("not_after")?, &i.bytes("payload")?)?;
            json!({"name": hex(&name.0), "record": hex(&record)})
        }
        "plain_open" => {
            let opened = open_plain(Timestamp(i.num("now")?), &i.bytes("record")?)?;
            json!({"not_after": t(opened.not_after), "payload": hex(&opened.payload)})
        }
        "keyring_write" => {
            let kek = zeroize::Zeroizing::new(i.arr::<32>("kek")?);
            let profile_id: [u8; 16] = i.arr("profile_id")?;
            let mut entries = Vec::new();
            for e in i.list("entries")? {
                let e = In(e);
                let kid = Kid::new(e.str("kid")?)?;
                let wrapper =
                    KeyFileWrapper::new(kek.clone(), FixedRandom::new(&e.bytes("nonce")?));
                let protected =
                    block_on(wrapper.wrap(&profile_id, &kid, &data_key(&e.bytes("dk")?)?))?;
                entries.push(WrappedKey {
                    kid,
                    created: Timestamp(e.num("created")?),
                    wrapper_id: wrapper.id().into(),
                    wrapped: protected,
                });
            }
            let file = KeyringFile {
                profile_id,
                current_kid: Kid::new(i.str("current_kid")?)?,
                index_kid: Kid::new(i.str("index_kid")?)?,
                entries,
            };
            let bytes = file.encode();
            KeyringFile::parse(&bytes)?;
            json!({"file": hex(&bytes)})
        }
        "keyring" => {
            let file = KeyringFile::parse(&i.bytes("file")?)?;
            let kek: [u8; 32] = i.arr("kek")?;
            let wrapper = KeyFileWrapper::new(zeroize::Zeroizing::new(kek), FixedRandom::new(&[]));
            // Keyring::open checks every entry; the corpus also wants the data keys.
            block_on(Keyring::open(&file, &wrapper, FixedRandom::new(&[])))?;
            let mut keys = Vec::new();
            for e in &file.entries {
                let key = block_on(wrapper.unwrap(&file.profile_id, &e.kid, &e.wrapped))?;
                keys.push(json!({"kid": e.kid.as_str(), "created": e.created.0, "wrapper": e.wrapper_id, "dk": hex(key.expose())}));
            }
            json!({"profile_id": hex(&file.profile_id), "current_kid": file.current_kid.as_str(), "index_kid": file.index_kid.as_str(), "keys": keys})
        }
        "kek_file" => {
            let mode = if i.has("mode") {
                Some(u32::try_from(i.num("mode")?).map_err(|_| bad("mode"))?)
            } else {
                None
            };
            json!({"kek": hex(parse_kek_file(&i.bytes("content")?, mode)?.as_slice())})
        }
        "record_file_write" => {
            let record = StoredRecord {
                value: i.bytes("value")?,
                expires_at: i.time("expires_at")?,
                tags: i.tags("tags")?,
            };
            json!({"file": hex(&encode_record(&record))})
        }
        "record_file" => {
            let r = parse_record(&i.bytes("file")?)?;
            json!({"expires_at": t(r.expires_at), "tags": tags_out(&r.tags), "value": hex(&r.value)})
        }
        "files_meta" => {
            let meta = FilesMeta::parse(&i.bytes("file")?)?;
            levels::check_open(u16_of(i.num("max")?)?, meta.level, meta.min_compatible)?;
            json!({"level": meta.level, "min_compatible": meta.min_compatible})
        }
        "db_level" => {
            levels::check_database(
                u16_of(i.num("max")?)?,
                u16_of(i.num("user_version")?)?,
                u16_of(i.num("level")?)?,
                u16_of(i.num("min_compatible")?)?,
            )?;
            json!({})
        }
        "profile" => profile(i)?,
        "capabilities" => {
            let Some(b) = backends.fresh(i.str("backend")?) else {
                return Err(Outcome::Unsupported);
            };
            let c = b.capabilities();
            json!({"atomic_take": c.atomic_take, "atomic_batch": c.atomic_batch, "indexed": c.indexed, "multi_process": c.multi_process})
        }
        "scenario" => {
            let Some(b) = backends.fresh(i.str("backend")?) else {
                return Err(Outcome::Unsupported);
            };
            let mut results = Vec::new();
            for step in i.list("steps")? {
                results.push(block_on(run_step(&b, &In(step)))?);
            }
            json!({"results": results})
        }
        _ => return Err(Outcome::Unsupported),
    })
}

fn u16_of(v: u64) -> R<u16> {
    u16::try_from(v).map_err(|_| bad("level"))
}

fn profile(i: &In<'_>) -> R<Value> {
    let platform = match i.str("os")? {
        "windows" => Platform::Windows,
        _ => Platform::Unix,
    };
    let env: Map<String, Value> =
        i.0.get("env")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
    let lookup = move |k: &str| env.get(k).and_then(Value::as_str).map(str::to_owned);
    let flag = if i.has("flag") {
        Some(i.str("flag")?)
    } else {
        None
    };
    let active = if i.has("active") {
        Some(i.str("active")?)
    } else {
        None
    };
    let home = if i.has("home") {
        Some(i.str("home")?)
    } else {
        None
    };
    let p = resolve(&Inputs {
        platform,
        flag,
        env: &lookup,
        active,
        home,
    })?;
    Ok(json!({
        "name": p.name, "from": p.from.as_str(), "active_file": p.active_file.unwrap_or_default(),
        "kek_file": p.kek_file, "keyring": p.keyring, "state_db": p.state_db, "cache_db": p.cache_db,
        "state_root": p.state_root, "cache_root": p.cache_root,
    }))
}

fn code_of(r: Result<(), StoreError>) -> Value {
    json!({"code": r.map_or_else(|e| e.code(), |()| "ok")})
}

fn name_of(i: &In<'_>, k: &str) -> Result<Name, StoreError> {
    let b = i
        .bytes(k)
        .map_err(|_| StoreError::InvalidArgument("name"))?;
    Name::try_from(b.as_slice())
}

fn ns_name(i: &In<'_>) -> Result<(Namespace, Name), StoreError> {
    let ns = i
        .str("ns")
        .map_err(|_| StoreError::InvalidArgument("namespace"))?;
    Ok((Namespace::new(ns)?, name_of(i, "name")?))
}

fn put_parts(i: &In<'_>) -> Result<(Namespace, Name, StoredRecord), StoreError> {
    let (ns, name) = ns_name(i)?;
    let bad_input = |_| StoreError::InvalidArgument("record");
    let tags = i.tags("tags").map_err(|e| match e {
        Outcome::Code(c) => c,
        _ => StoreError::InvalidArgument("tags"),
    })?;
    if tags.len() > 16 {
        return Err(StoreError::LimitExceeded("tags"));
    }
    Ok((
        ns,
        name,
        StoredRecord {
            value: i.bytes("value").map_err(bad_input)?,
            expires_at: i.time("expires_at").map_err(bad_input)?,
            tags,
        },
    ))
}

fn query_of(i: &In<'_>, ns: Namespace) -> Result<Query, StoreError> {
    let cursor = if i.has("cursor") {
        Some(name_of(i, "cursor")?)
    } else {
        None
    };
    let opt = |k: &str| i.has(k).then(|| i.num(k).ok().map(Timestamp)).flatten();
    Ok(Query {
        ns,
        filters: i
            .tags("filters")
            .map_err(|_| StoreError::InvalidArgument("filters"))?,
        from: opt("from"),
        to: opt("to"),
        limit: usize::try_from(i.num("limit").unwrap_or(0)).unwrap_or(0),
        cursor,
        now: Timestamp(i.num("now").unwrap_or(0)),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "one arm per operation of the scenarios"
)]
async fn run_step<B: Backend>(b: &B, s: &In<'_>) -> R<Value> {
    let now = Timestamp(s.num("now").unwrap_or(0));
    Ok(match s.str("op")? {
        "put" => code_of(
            async {
                let (ns, name, r) = put_parts(s)?;
                b.put(&ns, &name, r).await
            }
            .await,
        ),
        op @ ("get" | "take") => {
            let r = async {
                let (ns, name) = ns_name(s)?;
                if op == "get" {
                    b.get(&ns, &name, now).await
                } else {
                    b.take(&ns, &name, now).await
                }
            }
            .await;
            match r {
                Ok(r) => {
                    json!({"code": "ok", "value": hex(&r.value), "expires_at": t(r.expires_at)})
                }
                Err(e) => json!({"code": e.code()}),
            }
        }
        "delete" => code_of(
            async {
                let (ns, name) = ns_name(s)?;
                b.delete(&ns, &name).await
            }
            .await,
        ),
        "batch" => {
            let r = async {
                if !b.capabilities().atomic_batch {
                    return Err(StoreError::CapabilityMissing("atomic batch"));
                }
                let mut ops = Vec::new();
                for o in s
                    .list("ops")
                    .map_err(|_| StoreError::InvalidArgument("ops"))?
                {
                    let o = In(o);
                    ops.push(
                        match o.str("op").map_err(|_| StoreError::InvalidArgument("op"))? {
                            "put" => {
                                let (ns, name, r) = put_parts(&o)?;
                                BatchOp::Put(ns, name, r)
                            }
                            "delete" => {
                                let (ns, name) = ns_name(&o)?;
                                BatchOp::Delete(ns, name)
                            }
                            _ => return Err(StoreError::InvalidArgument("op")),
                        },
                    );
                }
                b.batch(ops).await
            }
            .await;
            code_of(r)
        }
        "query" => {
            let r = async {
                let ns = Namespace::new(
                    s.str("ns")
                        .map_err(|_| StoreError::InvalidArgument("namespace"))?,
                )?;
                b.query(&query_of(s, ns)?).await
            }
            .await;
            match r {
                Ok(page) => {
                    let mut out = json!({"code": "ok", "names": page.records.iter().map(|(n, _)| hex(&n.0)).collect::<Vec<_>>()});
                    if let Some(c) = page.cursor {
                        out["cursor"] = json!(hex(&c.0));
                    }
                    out
                }
                Err(e) => json!({"code": e.code()}),
            }
        }
        "cleanup" => match b
            .cleanup(
                now,
                usize::try_from(s.num("limit")?).map_err(|_| bad("limit"))?,
            )
            .await
        {
            Ok(n) => json!({"code": "ok", "removed": n}),
            Err(e) => json!({"code": e.code()}),
        },
        "fill" => {
            let ns = Namespace::new(s.str("ns")?)?;
            let seed = s.bytes("seed")?;
            let expires_at = s.time("expires_at")?;
            let count = u32::try_from(s.num("count")?).map_err(|_| bad("count"))?;
            let mut ops = Vec::new();
            for n in 0..count {
                let mut h = Sha256::new();
                h.update(&seed);
                h.update(n.to_be_bytes());
                ops.push(BatchOp::Put(
                    ns.clone(),
                    Name(h.finalize().into()),
                    StoredRecord {
                        value: n.to_be_bytes().to_vec(),
                        expires_at,
                        tags: Vec::new(),
                    },
                ));
            }
            if b.capabilities().atomic_batch {
                b.batch(ops).await?;
            } else {
                for op in ops {
                    if let BatchOp::Put(ns, name, r) = op {
                        b.put(&ns, &name, r).await?;
                    }
                }
            }
            json!({"code": "ok"})
        }
        "scan" => {
            let ns = Namespace::new(s.str("ns")?)?;
            let limit = usize::try_from(s.num("limit")?).map_err(|_| bad("limit"))?;
            let mut h = Sha256::new();
            let mut count = 0usize;
            let mut cursor = None;
            loop {
                let page = b
                    .query(&Query {
                        ns: ns.clone(),
                        filters: Vec::new(),
                        from: None,
                        to: None,
                        limit,
                        cursor,
                        now,
                    })
                    .await?;
                for (n, _) in &page.records {
                    h.update(n.0);
                }
                count += page.records.len();
                match page.cursor {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
            if s.0.get("count_only").and_then(Value::as_bool) == Some(true) {
                json!({"code": "ok", "count": count})
            } else {
                json!({"code": "ok", "count": count, "digest": hex(&h.finalize())})
            }
        }
        _ => return Err(bad("op")),
    })
}
