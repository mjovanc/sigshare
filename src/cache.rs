use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::RwLock;

pub(crate) struct TtlCache<V> {
    entries: Arc<RwLock<HashMap<String, CacheEntry<V>>>>,
    ttl: Duration,
}

struct CacheEntry<V> {
    value: V,
    inserted_at: Instant,
}

impl<V: Clone> TtlCache<V> {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    pub async fn get(&self, key: &str) -> Option<V> {
        let entries = self.entries.read().await;
        entries.get(key).and_then(|entry| {
            if entry.inserted_at.elapsed() < self.ttl { Some(entry.value.clone()) } else { None }
        })
    }

    pub async fn insert(&self, key: String, value: V) {
        let mut entries = self.entries.write().await;
        entries.insert(key, CacheEntry { value, inserted_at: Instant::now() });
    }

    pub async fn invalidate(&self, key: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(key);
    }
}
