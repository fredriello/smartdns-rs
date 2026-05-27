//! Daemon-side CFST manager.
//!
//! Reads `cfst-domain` rules from smartdns.conf, periodically refreshes
//! optimized IPs, and lets the CfstMiddleware answer A/AAAA queries from cache.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::cfst::{run_cfst, CfstConfig, CfstResult};

#[derive(Clone, Debug)]
pub struct CfstDomainConfig {
    pub domain: String,
    pub cfst: CfstConfig,
    pub refresh_interval: Duration,
    pub ttl: Duration,
    pub serve_stale: bool,
}

impl CfstDomainConfig {
    pub fn normalized_domain(&self) -> String {
        normalize_domain(&self.domain)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryFamily {
    V4,
    V6,
}

#[derive(Clone, Debug)]
pub struct CfstAnswer {
    pub ips: Arc<[IpAddr]>,
    pub ttl: Duration,
    pub stale: bool,
}

#[derive(Clone, Debug)]
struct CfstCacheEntry {
    results: Arc<[CfstResult]>,
    updated_at: Instant,
    expires_at: Instant,
}

#[derive(Clone, Debug, Default)]
pub struct CfstManager {
    rules: Arc<[CfstDomainConfig]>,
    cache: Arc<RwLock<HashMap<String, CfstCacheEntry>>>,
}

impl CfstManager {
    pub fn new(rules: Vec<CfstDomainConfig>) -> Self {
        Self {
            rules: Arc::from(rules),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Returns true if `qname` matches any configured cfst-domain.
    pub fn matches(&self, qname: &str) -> bool {
        let qname = normalize_domain(qname);
        self.rules
            .iter()
            .any(|r| domain_matches(&qname, &r.normalized_domain()))
    }

    /// Refresh every configured domain once (for preload).
    pub async fn refresh_all_once(&self) {
        for rule in self.rules.iter().cloned() {
            self.refresh_rule(&rule).await;
        }
    }

    /// Spawn background refresh loops.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut tasks = Vec::new();
            for rule in self.rules.iter().cloned() {
                let manager = self.clone();
                tasks.push(tokio::spawn(async move {
                    loop {
                        manager.refresh_rule(&rule).await;
                        tokio::time::sleep(rule.refresh_interval).await;
                    }
                }));
            }
            for task in tasks {
                let _ = task.await;
            }
        })
    }

    pub async fn lookup(&self, qname: &str, family: QueryFamily) -> Option<CfstAnswer> {
        let now = Instant::now();
        let qname = normalize_domain(qname);
        let cache = self.cache.read().await;

        let mut best: Option<(&CfstDomainConfig, &CfstCacheEntry)> = None;
        for rule in self.rules.iter() {
            let domain = rule.normalized_domain();
            if !domain_matches(&qname, &domain) {
                continue;
            }
            let Some(entry) = cache.get(&domain) else {
                continue;
            };
            if now > entry.expires_at && !rule.serve_stale {
                continue;
            }
            match best {
                None => best = Some((rule, entry)),
                Some((old_rule, _)) => {
                    if domain.len() > old_rule.normalized_domain().len() {
                        best = Some((rule, entry));
                    }
                }
            }
        }

        let (rule, entry) = best?;
        let ips: Vec<IpAddr> = entry
            .results
            .iter()
            .map(|r| r.ip)
            .filter(|ip| match (family, ip) {
                (QueryFamily::V4, IpAddr::V4(_)) => true,
                (QueryFamily::V6, IpAddr::V6(_)) => true,
                _ => false,
            })
            .collect();

        if ips.is_empty() {
            return None;
        }

        let stale = now > entry.expires_at;
        let ttl = if stale {
            Duration::from_secs(30)
        } else {
            rule.ttl
        };

        Some(CfstAnswer {
            ips: Arc::from(ips),
            ttl,
            stale,
        })
    }

    async fn refresh_rule(&self, rule: &CfstDomainConfig) {
        let domain = rule.normalized_domain();
        match run_cfst(rule.cfst.clone()).await {
            Ok(results) if !results.is_empty() => {
                let now = Instant::now();
                let entry = CfstCacheEntry {
                    results: Arc::from(results),
                    updated_at: now,
                    expires_at: now + rule.refresh_interval,
                };
                tracing::info!(
                    %domain,
                    count = entry.results.len(),
                    "cfst refresh done"
                );
                self.cache.write().await.insert(domain, entry);
            }
            Ok(_) => {
                tracing::warn!(%domain, "cfst refresh produced no usable IPs");
            }
            Err(err) => {
                tracing::warn!(%domain, error = ?err, "cfst refresh failed");
            }
        }
    }
}

fn normalize_domain(input: &str) -> String {
    input
        .trim()
        .trim_matches('/')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn domain_matches(qname: &str, rule: &str) -> bool {
    qname == rule || qname.ends_with(&format!(".{rule}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_config_domains() {
        assert_eq!(normalize_domain("/CDN.Example.COM./"), "cdn.example.com");
    }

    #[test]
    fn suffix_match_is_label_aware() {
        assert!(domain_matches("cdn.example.com", "example.com"));
        assert!(domain_matches("example.com", "example.com"));
        assert!(!domain_matches("badexample.com", "example.com"));
    }
}
