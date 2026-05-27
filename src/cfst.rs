use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::config::{CfstConfig, CfstDomainEntry, CfstMode, Domain};
use crate::libdns::proto::rr::Name;
use crate::log::{error, info, warn};

/// Results of a CFST speed test for a single domain.
#[derive(Debug, Clone)]
pub struct CfstResults {
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
    pub updated_at: Instant,
    pub stale: bool,
}

impl CfstResults {
    pub fn has_ipv4(&self) -> bool {
        !self.ipv4.is_empty()
    }

    pub fn has_ipv6(&self) -> bool {
        !self.ipv6.is_empty()
    }
}

/// Manages periodic CFST speed tests and caches results.
pub struct CfstManager {
    config: Arc<CfstConfig>,
    domains: Vec<CfstDomainEntry>,
    pub(crate) results: Arc<RwLock<HashMap<Name, CfstResults>>>,
    domain_names: Vec<Name>,
}

impl CfstManager {
    pub fn new(config: CfstConfig, domains: Vec<CfstDomainEntry>) -> Arc<Self> {
        let domain_names: Vec<Name> = domains
            .iter()
            .filter_map(|entry| domain_to_name(&entry.domain))
            .collect();

        Arc::new(Self {
            config: Arc::new(config),
            domains,
            results: Arc::new(RwLock::new(HashMap::new())),
            domain_names,
        })
    }

    /// Spawns a background task that periodically refreshes all domains.
    ///
    /// Note: if `refresh_interval` is configured shorter than the time a full
    /// refresh takes, and preload is also enabled, both tasks may overlap and
    /// write interleaved results. For the default 1-hour interval this is not
    /// a concern in practice.
    pub fn start(self: Arc<Self>) -> JoinHandle<()> {
        let interval = self.config.refresh_interval();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                self.refresh_all_once().await;
            }
        })
    }

    /// Run a single refresh pass for all configured domains.
    pub async fn refresh_all_once(&self) {
        for entry in &self.domains {
            self.refresh_domain(entry).await;
        }
    }

    /// Refresh results for a single domain entry.
    async fn refresh_domain(&self, entry: &CfstDomainEntry) {
        let domain_name = match domain_to_name(&entry.domain) {
            Some(name) => name,
            None => {
                warn!("cfst: unable to convert domain entry to Name");
                return;
            }
        };

        // Determine IP file path: per-domain override or global
        let ip_file = entry.ip_file.as_ref().or(self.config.ip_file.as_ref());

        let ip_file = match ip_file {
            Some(path) => path,
            None => {
                warn!(
                    "cfst: no ip_file configured for domain={}",
                    domain_name.to_string().trim_end_matches('.')
                );
                return;
            }
        };

        // Read and parse the IP file
        let content = match std::fs::read_to_string(ip_file) {
            Ok(c) => c,
            Err(e) => {
                error!("cfst: failed to read ip_file={}: {}", ip_file.display(), e);
                // Mark results as stale if they existed before
                let mut results = self.results.write().await;
                if let Some(r) = results.get_mut(&domain_name) {
                    r.stale = true;
                }
                return;
            }
        };

        let candidate_count = self.config.candidate_count();
        let (ipv4_candidates, ipv6_candidates) = parse_ip_content(&content, candidate_count);

        let total_candidates = ipv4_candidates.len() + ipv6_candidates.len();
        info!(
            "cfst refresh start domain={} candidates={}",
            domain_name.to_string().trim_end_matches('.'),
            total_candidates
        );

        // Determine port from config mode
        let port = self
            .config
            .mode
            .as_ref()
            .and_then(|modes| {
                modes.iter().find_map(|m| match m {
                    CfstMode::Tcp(p) => Some(*p),
                    _ => None,
                })
            })
            .unwrap_or(443);

        // Warn if unsupported modes are configured
        if let Some(modes) = self.config.mode.as_ref() {
            let has_unsupported = modes
                .iter()
                .any(|m| matches!(m, CfstMode::Httping | CfstMode::Download));
            if has_unsupported {
                warn!(
                    "cfst: httping and download modes are not yet implemented, falling back to TCP"
                );
            }
        }

        let result_count = entry
            .result_count
            .unwrap_or_else(|| self.config.result_count());
        let concurrency = self.config.concurrency();
        let ping_times = self.config.ping_times();

        // Test IPv4 candidates
        // TODO: min_speed filtering not yet implemented for TCP-only mode
        let best_ipv4 = if !ipv4_candidates.is_empty() {
            test_candidates_v4(
                &ipv4_candidates,
                port,
                concurrency,
                ping_times,
                result_count,
            )
            .await
        } else {
            Vec::new()
        };

        // Test IPv6 candidates
        let best_ipv6 = if !ipv6_candidates.is_empty() {
            test_candidates_v6(
                &ipv6_candidates,
                port,
                concurrency,
                ping_times,
                result_count,
            )
            .await
        } else {
            Vec::new()
        };

        let best_latency_str = "N/A".to_string();
        let total_results = best_ipv4.len() + best_ipv6.len();

        info!(
            "cfst refresh done domain={} results={} best_latency={}",
            domain_name.to_string().trim_end_matches('.'),
            total_results,
            best_latency_str
        );

        // Store results
        let results_entry = CfstResults {
            ipv4: best_ipv4,
            ipv6: best_ipv6,
            updated_at: Instant::now(),
            stale: false,
        };

        let mut results = self.results.write().await;
        results.insert(domain_name, results_entry);
    }

    /// Get cached results for a domain.
    pub async fn get_results(&self, domain: &Name) -> Option<CfstResults> {
        let results = self.results.read().await;
        results.get(domain).cloned()
    }

    /// Get all cached results.
    pub async fn all_results(&self) -> HashMap<Name, CfstResults> {
        let results = self.results.read().await;
        results.clone()
    }

    /// Check if a queried domain matches any configured cfst-domain entry.
    pub fn has_domain(&self, domain: &Name) -> bool {
        for entry in &self.domains {
            match &entry.domain {
                Domain::Name(wildcard_name) => {
                    if wildcard_name.is_match(domain) {
                        return true;
                    }
                }
                Domain::Set(_) => {
                    // Domain sets not supported for cfst matching currently
                }
            }
        }
        false
    }

    /// Find the matching Name key for a queried domain.
    pub fn find_matching_name(&self, domain: &Name) -> Option<&Name> {
        for (i, entry) in self.domains.iter().enumerate() {
            match &entry.domain {
                Domain::Name(wildcard_name) => {
                    if wildcard_name.is_match(domain) {
                        return self.domain_names.get(i);
                    }
                }
                Domain::Set(_) => {}
            }
        }
        None
    }
}

/// Convert a Domain to a DNS Name for use as a cache key.
fn domain_to_name(domain: &Domain) -> Option<Name> {
    match domain {
        Domain::Name(wildcard_name) => {
            let name: &Name = wildcard_name;
            Some(name.clone())
        }
        Domain::Set(_) => None,
    }
}

/// Parse IP file content into IPv4 and IPv6 candidate lists.
/// Each line can be an IP address or a CIDR range.
/// For CIDR ranges, hosts are enumerated up to candidate_count total.
pub fn parse_ip_content(content: &str, candidate_count: usize) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    use ipnet::IpNet;
    use std::net::IpAddr;

    let mut ipv4_candidates: Vec<Ipv4Addr> = Vec::new();
    let mut ipv6_candidates: Vec<Ipv6Addr> = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let total = ipv4_candidates.len() + ipv6_candidates.len();
        if total >= candidate_count {
            break;
        }

        // Try parsing as CIDR first
        if let Ok(net) = line.parse::<IpNet>() {
            let remaining = candidate_count - total;
            match net {
                IpNet::V4(v4net) => {
                    for host in v4net.hosts().take(remaining) {
                        ipv4_candidates.push(host);
                    }
                }
                IpNet::V6(v6net) => {
                    for host in v6net.hosts().take(remaining) {
                        ipv6_candidates.push(host);
                    }
                }
            }
        } else if let Ok(ip) = line.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => ipv4_candidates.push(v4),
                IpAddr::V6(v6) => ipv6_candidates.push(v6),
            }
        }
        // Skip unparseable lines
    }

    (ipv4_candidates, ipv6_candidates)
}

/// Test IPv4 candidates via TCP connect and return the fastest ones.
async fn test_candidates_v4(
    candidates: &[Ipv4Addr],
    port: u16,
    concurrency: usize,
    ping_times: usize,
    result_count: usize,
) -> Vec<Ipv4Addr> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(candidates.len());

    for &ip in candidates {
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let addr = SocketAddr::from((ip, port));
            let avg = measure_tcp_latency(addr, ping_times).await?;
            Some((ip, avg))
        });
        handles.push(handle);
    }

    let mut results: Vec<(Ipv4Addr, Duration)> = Vec::new();
    for handle in handles {
        if let Ok(Some((ip, latency))) = handle.await {
            results.push((ip, latency));
        }
    }

    results.sort_by(|a, b| a.1.cmp(&b.1));
    results
        .into_iter()
        .take(result_count)
        .map(|(ip, _)| ip)
        .collect()
}

/// Test IPv6 candidates via TCP connect and return the fastest ones.
async fn test_candidates_v6(
    candidates: &[Ipv6Addr],
    port: u16,
    concurrency: usize,
    ping_times: usize,
    result_count: usize,
) -> Vec<Ipv6Addr> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(candidates.len());

    for &ip in candidates {
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let addr = SocketAddr::from((ip, port));
            let avg = measure_tcp_latency(addr, ping_times).await?;
            Some((ip, avg))
        });
        handles.push(handle);
    }

    let mut results: Vec<(Ipv6Addr, Duration)> = Vec::new();
    for handle in handles {
        if let Ok(Some((ip, latency))) = handle.await {
            results.push((ip, latency));
        }
    }

    results.sort_by(|a, b| a.1.cmp(&b.1));
    results
        .into_iter()
        .take(result_count)
        .map(|(ip, _)| ip)
        .collect()
}

/// Measure average TCP connect latency to the given address.
/// Returns None if all attempts fail.
async fn measure_tcp_latency(addr: SocketAddr, ping_times: usize) -> Option<Duration> {
    let timeout_duration = Duration::from_secs(5);
    let mut total = Duration::ZERO;
    let mut success_count = 0u32;

    for _ in 0..ping_times {
        let start = Instant::now();
        let result = tokio::time::timeout(timeout_duration, TcpStream::connect(addr)).await;
        match result {
            Ok(Ok(_stream)) => {
                total += start.elapsed();
                success_count += 1;
            }
            _ => {}
        }
    }

    if success_count > 0 {
        Some(total / success_count)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_content_cidr() {
        let content = "173.245.48.0/20\n103.21.244.0/22\n";
        let (ipv4, ipv6) = parse_ip_content(content, 100);
        assert!(!ipv4.is_empty());
        assert!(ipv6.is_empty());
        // /20 has 4094 hosts, but we cap at 100
        assert_eq!(ipv4.len(), 100);
    }

    #[test]
    fn test_parse_ip_content_individual() {
        let content = "1.2.3.4\n5.6.7.8\n";
        let (ipv4, ipv6) = parse_ip_content(content, 100);
        assert_eq!(ipv4.len(), 2);
        assert!(ipv4.contains(&"1.2.3.4".parse().unwrap()));
        assert!(ipv4.contains(&"5.6.7.8".parse().unwrap()));
        assert!(ipv6.is_empty());
    }

    #[test]
    fn test_parse_ip_content_mixed() {
        let content = "1.2.3.4\n173.245.48.0/20\n";
        let (ipv4, ipv6) = parse_ip_content(content, 1024);
        // Individual IP should be first since it appears before CIDR
        assert!(ipv4.contains(&"1.2.3.4".parse().unwrap()));
        assert!(ipv6.is_empty());
    }

    #[test]
    fn test_parse_ip_content_comments_and_empty_lines() {
        let content = "# This is a comment\n\n1.2.3.4\n# another comment\n5.6.7.8\n";
        let (ipv4, _) = parse_ip_content(content, 100);
        assert_eq!(ipv4.len(), 2);
    }

    #[test]
    fn test_parse_ip_content_ipv6() {
        let content = "2400:cb00::/32\n";
        let (ipv4, ipv6) = parse_ip_content(content, 100);
        assert!(ipv4.is_empty());
        assert_eq!(ipv6.len(), 100);
    }

    #[test]
    fn test_parse_ip_content_with_test_fixture() {
        let content = std::fs::read_to_string("tests/test_data/cf-ipv4.txt")
            .expect("test fixture cf-ipv4.txt should exist");
        let (ipv4, ipv6) = parse_ip_content(&content, 1024);
        assert!(!ipv4.is_empty());
        assert!(ipv6.is_empty());
        assert!(ipv4.len() <= 1024);
    }
}
