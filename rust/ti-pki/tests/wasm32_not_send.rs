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

//! decision-15: host traits carry no `Send` bound, so a browser host implements them over
//! single-threaded APIs. This file compiles only for wasm32, where `MaybeSend` and
//! `MaybeSync` bind nothing: every loader takes hosts that are neither `Send` nor `Sync`
//! (each holds an `Rc`). `just wasm32` type-checks it; the bounds are the proof.

#![cfg(all(target_arch = "wasm32", feature = "load"))]

use std::cell::Cell;
use std::rc::Rc;

use futures_lite::future::block_on;
use ti_pki::load::{
    Artifact, ArtifactRequest, ArtifactResponse, CacheEntry, CacheError, CachePolicy, CacheStore,
    CachingLoader, Conditional, FallbackLoader, Fetched, HttpLoader, LoadError, Loader,
    PostRequest, ReloadPolicy, Reloader, Timestamp, Transport, TransportError, TransportErrorKind,
    read_back,
};
use ti_pki::{Tier, TrustConfig};

fn refused() -> TransportError {
    TransportError {
        kind: TransportErrorKind::Network,
        message: "offline".to_owned(),
        retryable: false,
    }
}

/// A browser's fetch, shared within its one thread.
struct Fetch(Rc<Cell<usize>>);

impl Transport for Fetch {
    async fn get(&self, _: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
        self.0.set(self.0.get() + 1);
        Err(refused())
    }

    async fn post(&self, _: &PostRequest<'_>) -> Result<Vec<u8>, TransportError> {
        self.0.set(self.0.get() + 1);
        Err(refused())
    }
}

/// A browser's storage, shared within its one thread.
struct Storage(Rc<Cell<usize>>);

impl CacheStore for Storage {
    async fn get(&self, _: &str) -> Result<Option<CacheEntry>, CacheError> {
        self.0.set(self.0.get() + 1);
        Ok(None)
    }

    async fn put(&self, _: &str, _: &CacheEntry) -> Result<(), CacheError> {
        self.0.set(self.0.get() + 1);
        Ok(())
    }
}

/// A loader of the host's own.
struct Own(Rc<Cell<usize>>);

impl Loader for Own {
    async fn fetch(&self, _: Artifact, _: Conditional<'_>) -> Result<Fetched, LoadError> {
        self.0.set(self.0.get() + 1);
        Err(LoadError::Transport(refused()))
    }
}

#[test]
fn the_loaders_take_hosts_that_are_not_send() {
    let calls = Rc::new(Cell::new(0));
    let clock = Rc::new(Cell::new(1_767_225_600));
    let now = {
        let clock = clock.clone();
        move || Timestamp(clock.get())
    };
    let config = TrustConfig::preset_prod();
    let http = HttpLoader::new(&config, Fetch(calls.clone()), now.clone());
    let cached = CachingLoader::new(
        http,
        Storage(calls.clone()),
        now.clone(),
        CachePolicy::default(),
    );
    let loader = FallbackLoader::new(cached, Own(calls.clone()));
    let reloader = Reloader::new(
        config.clone(),
        Tier::Prod,
        loader,
        now.clone(),
        ReloadPolicy::default(),
    )
    .unwrap();
    block_on(reloader.tick());
    let _ = block_on(read_back(&config, Storage(calls.clone()), &now, true));
    assert!(calls.get() > 0);
}
