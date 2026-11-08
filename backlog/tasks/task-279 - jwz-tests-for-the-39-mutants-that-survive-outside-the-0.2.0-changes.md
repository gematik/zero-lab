---
id: TASK-279
title: 'jwz: tests for the 39 mutants that survive outside the 0.2.0 changes'
status: To Do
assignee: []
created_date: '2026-11-08T16:57:00Z'
labels:
  - jwz
  - testing
dependencies: []
priority: medium
ordinal: 295000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The mutation run for jwz 0.2.0 (TASK-272, 2026-11-08, score 0.9359 before the Error test) left 44 mutants alive; 2 were on lines 0.2.0 changed (Error's PartialEq, tested in TASK-272 together with 3 more in error.rs). These 39 sit on lines the release did not touch, so no test of the changed code catches them. Worth looking at first: Jwe<Decrypted>::into_plaintext (a test reads plaintext(), never into_plaintext), JwkSet::by_kid and curve_for (== to != survives), JwkSet::parse's skip guard, jwe::agreement and entries (&& to ||), the strict JSON visitor, the Extended and Blocking backend adapters, and the key_id defaults of the key traits. Each either gets a test named after the rule it proves, or is recorded as an equivalent mutant (cargo-mutants exclusion with the reason) if no behaviour can tell it apart.

- `src/crypto/asynchronous.rs:313` <impl AsyncKeyWrap for Blocking<'_, T>>::kek_len: → `0`
- `src/crypto/asynchronous.rs:313` <impl AsyncKeyWrap for Blocking<'_, T>>::kek_len: → `1`
- `src/crypto/asynchronous.rs:344` <impl AsyncBackend for B>::ecdsa_async: → `None`
- `src/crypto/asynchronous.rs:356` <impl AsyncBackend for B>::aead_async: → `None`
- `src/crypto/asynchronous.rs:360` <impl AsyncBackend for B>::key_wrap_async: → `None`
- `src/crypto/extended.rs:77` <impl Backend for Extended<B>>::mac: → `None`
- `src/crypto/extended.rs:81` <impl Backend for Extended<B>>::ecdsa: → `!=`
- `src/crypto/extended.rs:81` <impl Backend for Extended<B>>::ecdsa: → `None`
- `src/crypto/extended.rs:88` <impl Backend for Extended<B>>::eddsa: → `None`
- `src/crypto/extended.rs:103` <impl Backend for Extended<B>>::key_wrap: → `None`
- `src/json.rs:94` <impl Visitor<'de> for StrictVisitor>::expecting: → `Ok(Default::default())`
- `src/json.rs:98` <impl Visitor<'de> for StrictVisitor>::visit_bool: → `Ok(Default::default())`
- `src/json.rs:102` <impl Visitor<'de> for StrictVisitor>::visit_i64: → `Ok(Default::default())`
- `src/json.rs:120` <impl Visitor<'de> for StrictVisitor>::visit_string: → `Ok(Default::default())`
- `src/json.rs:124` <impl Visitor<'de> for StrictVisitor>::visit_unit: → `Ok(Default::default())`
- `src/json.rs:128` <impl Visitor<'de> for StrictVisitor>::visit_none: → `Ok(Default::default())`
- `src/jwe/mod.rs:424` Jwe<Decrypted>::into_plaintext: → `Zeroizing::from(vec![0])`
- `src/jwe/mod.rs:424` Jwe<Decrypted>::into_plaintext: → `Zeroizing::from(vec![1])`
- `src/jwe/mod.rs:424` Jwe<Decrypted>::into_plaintext: → `Zeroizing::from(vec![])`
- `src/jwe/mod.rs:424` Jwe<Decrypted>::into_plaintext: → `Zeroizing::new(vec![0])`
- `src/jwe/mod.rs:424` Jwe<Decrypted>::into_plaintext: → `Zeroizing::new(vec![1])`
- `src/jwe/mod.rs:424` Jwe<Decrypted>::into_plaintext: → `Zeroizing::new(vec![])`
- `src/jwe/mod.rs:483` agreement: → `||`
- `src/jwe/mod.rs:523` entries: → `||`
- `src/jwe/mod.rs:699` encrypt: → ``
- `src/jwk.rs:402` Jwk::public: → ``
- `src/jwk.rs:549` JwkSet::parse: → `true`
- `src/jwk.rs:560` JwkSet::by_kid: → `!=`
- `src/jwk.rs:632` curve_for: → `!=`
- `src/keys/mod.rs:123` <impl From<Signature> for Vec<u8>>::from: → `Default::default()`
- `src/keys/mod.rs:144` JwsKey::key_id: → `Some("")`
- `src/keys/mod.rs:144` JwsKey::key_id: → `Some("xyzzy")`
- `src/keys/mod.rs:222` KeyAgreement::key_id: → `Some("")`
- `src/keys/mod.rs:222` KeyAgreement::key_id: → `Some("xyzzy")`
- `src/keys/mod.rs:238` AsyncKeyAgreement::key_id: → `Some("")`
- `src/keys/mod.rs:238` AsyncKeyAgreement::key_id: → `Some("xyzzy")`
- `src/keys/mod.rs:252` <impl AsyncKeyAgreement for T>::key_id: → `None`
- `src/keys/mod.rs:252` <impl AsyncKeyAgreement for T>::key_id: → `Some("")`
- `src/keys/mod.rs:252` <impl AsyncKeyAgreement for T>::key_id: → `Some("xyzzy")`
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each of the 39 is caught by a test named after the rule it proves, or excluded as equivalent with the reason in the mutants config
- [ ] #2 jwz's mutation score is re-recorded and the gate passes
<!-- AC:END -->
