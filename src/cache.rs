//! TTL-based in-memory cache.
//!
//! Used internally by [`crate::SsfClient`] to cache
//! [`crate::ssf::TransmitterConfiguration`] per issuer so that stream
//! management and delivery calls don't re-fetch discovery on every request.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::RwLock;

/// A concurrency-safe, TTL-expiring cache keyed by [`String`].
///
/// Entries are silently treated as absent once their TTL has elapsed.
/// No background eviction — stale entries are filtered on read and
/// overwritten on insert.
pub(crate) struct TtlCache<V> {
    entries: Arc<RwLock<HashMap<String, CacheEntry<V>>>>,
    ttl: Duration,
}

/// A cached value paired with its insertion timestamp.
struct CacheEntry<V> {
    value: V,
    inserted_at: Instant,
}

impl<V: Clone> TtlCache<V> {
    /// Create a new cache where entries expire after `ttl`.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Retrieve a cached value if it exists and has not expired.
    ///
    /// Returns `None` for missing keys *and* for expired entries.
    pub async fn get(&self, key: &str) -> Option<V> {
        let entries = self.entries.read().await;
        entries.get(key).and_then(|entry| {
            if entry.inserted_at.elapsed() < self.ttl { Some(entry.value.clone()) } else { None }
        })
    }

    /// Insert or overwrite a cache entry, resetting its TTL.
    pub async fn insert(&self, key: String, value: V) {
        let mut entries = self.entries.write().await;
        entries.insert(key, CacheEntry { value, inserted_at: Instant::now() });
    }

    /// Remove an entry immediately, regardless of remaining TTL.
    pub async fn invalidate(&self, key: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(key);
    }
}
