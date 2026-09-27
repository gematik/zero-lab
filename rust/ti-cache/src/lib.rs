#![doc = include_str!("../README.md")]

mod cache;
mod store;

pub use cache::{Cache, CacheLookupError, CachePolicy, Cached, Conditional, OriginResponse};
pub use store::{CacheEntry, CacheError, CacheStore, MemoryCacheStore, Meta, Source};
