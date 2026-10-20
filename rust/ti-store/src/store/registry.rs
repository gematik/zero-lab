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

//! The namespace registry of spec/store.

use super::backend::Capabilities;

/// Whether a namespace's records are sealed (STORE-021).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Sealed records; needs a keyring.
    Sealed,
    /// Plain records; for data whose consumer verifies it on every read (STORE-025).
    Plain,
}

/// Which database holds a namespace (STORE-021).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Database {
    /// `state.db`: kept.
    State,
    /// `cache.db`: may be lost at any time.
    Cache,
}

/// A registered namespace and its record type (STORE-022).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespaceSpec {
    /// The namespace.
    pub name: &'static str,
    /// Sealed or plain.
    pub kind: Kind,
    /// Its database.
    pub database: Database,
    /// The longest lifetime of a record in seconds; 0 for none.
    pub max_ttl: u64,
    /// The fields that may be indexed.
    pub fields: &'static [&'static str],
    /// What the backend must offer.
    pub requires: Capabilities,
}

const DAY: u64 = 86_400;
const NONE: Capabilities = Capabilities {
    atomic_take: false,
    atomic_batch: false,
    indexed: false,
    multi_process: false,
};

const fn spec(
    name: &'static str,
    kind: Kind,
    database: Database,
    max_ttl: u64,
    fields: &'static [&'static str],
) -> NamespaceSpec {
    NamespaceSpec {
        name,
        kind,
        database,
        max_ttl,
        fields,
        requires: NONE,
    }
}

/// Access tokens with their DPoP binding reference.
pub const OAUTH_ACCESS: NamespaceSpec = spec(
    "oauth.access",
    Kind::Sealed,
    Database::State,
    DAY,
    &["issuer", "audience", "subject"],
);
/// Refresh tokens.
pub const OAUTH_REFRESH: NamespaceSpec = spec(
    "oauth.refresh",
    Kind::Sealed,
    Database::State,
    90 * DAY,
    &["issuer", "subject"],
);
/// PoPP tokens.
pub const POPP: NamespaceSpec = spec(
    "popp",
    Kind::Sealed,
    Database::State,
    DAY,
    &["kvnr", "iccsn"],
);
/// Comfort-signature user IDs.
pub const COMFORT: NamespaceSpec =
    spec("comfort", Kind::Sealed, Database::State, 0, &["konnektor"]);
/// TSL rollback state; sealed for integrity.
pub const TSL_STATE: NamespaceSpec = spec("tsl.state", Kind::Sealed, Database::State, 0, &[]);
/// Discovery documents and entity statements.
pub const WELL_KNOWN: NamespaceSpec = spec(
    "well-known",
    Kind::Plain,
    Database::Cache,
    7 * DAY,
    &["issuer"],
);
/// TSL bytes as downloaded.
pub const PKI_TSL: NamespaceSpec = spec("pki.tsl", Kind::Plain, Database::Cache, 30 * DAY, &[]);
/// Root certificate bundles as downloaded.
pub const PKI_ROOTS: NamespaceSpec = spec("pki.roots", Kind::Plain, Database::Cache, 30 * DAY, &[]);
/// OCSP responses.
pub const PKI_OCSP: NamespaceSpec = spec(
    "pki.ocsp",
    Kind::Plain,
    Database::Cache,
    7 * DAY,
    &["issuer"],
);
/// Konnektor service directories.
pub const CONNECTOR_SDS: NamespaceSpec =
    spec("connector.sds", Kind::Plain, Database::Cache, DAY, &[]);

/// Every registered namespace.
pub const ALL: &[NamespaceSpec] = &[
    OAUTH_ACCESS,
    OAUTH_REFRESH,
    POPP,
    COMFORT,
    TSL_STATE,
    WELL_KNOWN,
    PKI_TSL,
    PKI_ROOTS,
    PKI_OCSP,
    CONNECTOR_SDS,
];

/// The registered namespace of that name.
pub fn lookup(name: &str) -> Option<&'static NamespaceSpec> {
    ALL.iter().find(|s| s.name == name)
}
