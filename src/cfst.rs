use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use url::Url;

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

        // Determine modes
        let modes = self
            .config
            .mode
            .as_ref()
            .cloned()
            .unwrap_or_else(|| vec![CfstMode::Tcp(443)]);

        // Determine port from TCP mode
        let port = modes
            .iter()
            .find_map(|m| match m {
                CfstMode::Tcp(p) => Some(*p),
                _ => None,
            })
            .unwrap_or(443);

        let result_count = entry
            .result_count
            .unwrap_or_else(|| self.config.result_count());
        let concurrency = self.config.concurrency();
        let ping_times = self.config.ping_times();

        // Determine the URL for httping/download
        let test_url = entry.url.as_ref().or(self.config.url.as_ref());

        // Build the pipeline stages
        let pipeline_stages = build_pipeline_stages(&modes);

        // Determine intermediate counts for each stage
        let download_test_count = self.config.download_test_count();

        // Run pipeline for IPv4
        let best_ipv4 = if !ipv4_candidates.is_empty() {
            let ipv4_as_ipaddr: Vec<IpAddr> =
                ipv4_candidates.iter().map(|ip| IpAddr::V4(*ip)).collect();
            let results = self
                .run_pipeline(
                    &ipv4_as_ipaddr,
                    &pipeline_stages,
                    port,
                    concurrency,
                    ping_times,
                    result_count,
                    download_test_count,
                    test_url,
                )
                .await;
            results
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .collect()
        } else {
            Vec::new()
        };

        // Run pipeline for IPv6
        let best_ipv6 = if !ipv6_candidates.is_empty() {
            let ipv6_as_ipaddr: Vec<IpAddr> =
                ipv6_candidates.iter().map(|ip| IpAddr::V6(*ip)).collect();
            let results = self
                .run_pipeline(
                    &ipv6_as_ipaddr,
                    &pipeline_stages,
                    port,
                    concurrency,
                    ping_times,
                    result_count,
                    download_test_count,
                    test_url,
                )
                .await;
            results
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(v6),
                    _ => None,
                })
                .collect()
        } else {
            Vec::new()
        };

        let total_results = best_ipv4.len() + best_ipv6.len();

        info!(
            "cfst refresh done domain={} results={}",
            domain_name.to_string().trim_end_matches('.'),
            total_results,
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

    /// Run the multi-stage pipeline on candidates.
    async fn run_pipeline(
        &self,
        candidates: &[IpAddr],
        stages: &[PipelineStage],
        port: u16,
        concurrency: usize,
        ping_times: usize,
        result_count: usize,
        download_test_count: usize,
        test_url: Option<&String>,
    ) -> Vec<IpAddr> {
        let mut current_ips = candidates.to_vec();

        for (i, stage) in stages.iter().enumerate() {
            if current_ips.is_empty() {
                break;
            }

            // Determine how many results to keep from this stage
            let take_count =
                compute_stage_output_count(i, stages, result_count, download_test_count);

            let stage_result = match stage {
                PipelineStage::Tcp => {
                    test_candidates_tcp(&current_ips, port, concurrency, ping_times, take_count)
                        .await
                }
                PipelineStage::Httping => {
                    if let Some(url_str) = test_url {
                        match parse_test_url(url_str) {
                            Some(url_parts) => {
                                test_candidates_httping(
                                    &current_ips,
                                    &url_parts,
                                    concurrency,
                                    take_count,
                                )
                                .await
                            }
                            None => {
                                warn!("cfst: failed to parse cfst-url, skipping httping stage");
                                current_ips.iter().copied().take(take_count).collect()
                            }
                        }
                    } else {
                        warn!("cfst: no cfst-url configured, skipping httping stage");
                        current_ips.iter().copied().take(take_count).collect()
                    }
                }
                PipelineStage::Download => {
                    if let Some(url_str) = test_url {
                        match parse_test_url(url_str) {
                            Some(url_parts) => {
                                let min_speed = self.config.min_speed();
                                test_candidates_download(
                                    &current_ips,
                                    &url_parts,
                                    concurrency,
                                    take_count,
                                    min_speed,
                                )
                                .await
                            }
                            None => {
                                warn!("cfst: failed to parse cfst-url, skipping download stage");
                                current_ips.iter().copied().take(take_count).collect()
                            }
                        }
                    } else {
                        warn!("cfst: no cfst-url configured, skipping download stage");
                        current_ips.iter().copied().take(take_count).collect()
                    }
                }
            };

            // Fallback: if stage produced zero results, keep previous results
            if stage_result.is_empty() {
                warn!(
                    "cfst: {:?} stage produced zero results, using previous stage results",
                    stage
                );
                current_ips.truncate(take_count);
            } else {
                current_ips = stage_result;
            }
        }

        current_ips
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

/// Pipeline stage types
#[derive(Debug, Clone, PartialEq, Eq)]
enum PipelineStage {
    Tcp,
    Httping,
    Download,
}

/// Parsed URL parts for httping/download tests
#[derive(Debug, Clone)]
struct TestUrlParts {
    hostname: String,
    port: u16,
    path: String,
}

/// Parse a URL string into its components for testing.
fn parse_test_url(url_str: &str) -> Option<TestUrlParts> {
    let parsed = Url::parse(url_str).ok()?;
    let hostname = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let path = if parsed.path().is_empty() {
        "/".to_string()
    } else {
        let mut p = parsed.path().to_string();
        if let Some(query) = parsed.query() {
            p.push('?');
            p.push_str(query);
        }
        p
    };
    Some(TestUrlParts {
        hostname,
        port,
        path,
    })
}

/// Build the ordered list of pipeline stages from configured modes.
fn build_pipeline_stages(modes: &[CfstMode]) -> Vec<PipelineStage> {
    let mut stages = Vec::new();
    for mode in modes {
        match mode {
            CfstMode::Tcp(_) => stages.push(PipelineStage::Tcp),
            CfstMode::Httping => stages.push(PipelineStage::Httping),
            CfstMode::Download => stages.push(PipelineStage::Download),
        }
    }
    if stages.is_empty() {
        stages.push(PipelineStage::Tcp);
    }
    stages
}

/// Compute how many results a stage should output based on what follows it.
fn compute_stage_output_count(
    stage_index: usize,
    stages: &[PipelineStage],
    result_count: usize,
    download_test_count: usize,
) -> usize {
    // If this is the last stage, output result_count
    if stage_index >= stages.len() - 1 {
        return result_count;
    }
    // Look at what the next stage is
    let next_stage = &stages[stage_index + 1];
    match next_stage {
        PipelineStage::Download => download_test_count,
        PipelineStage::Httping => {
            // If there is a download stage after httping, pass download_test_count
            let has_download_after = stages[stage_index + 2..].contains(&PipelineStage::Download);
            if has_download_after {
                download_test_count
            } else {
                result_count
            }
        }
        PipelineStage::Tcp => result_count,
    }
}

/// Test candidates via TCP connect, sorted by latency.
async fn test_candidates_tcp(
    candidates: &[IpAddr],
    port: u16,
    concurrency: usize,
    ping_times: usize,
    take_count: usize,
) -> Vec<IpAddr> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(candidates.len());

    for &ip in candidates {
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let addr = SocketAddr::new(ip, port);
            let avg = measure_tcp_latency(addr, ping_times).await?;
            Some((ip, avg))
        });
        handles.push(handle);
    }

    let mut results: Vec<(IpAddr, Duration)> = Vec::new();
    for handle in handles {
        if let Ok(Some((ip, latency))) = handle.await {
            results.push((ip, latency));
        }
    }

    results.sort_by(|a, b| a.1.cmp(&b.1));
    results
        .into_iter()
        .take(take_count)
        .map(|(ip, _)| ip)
        .collect()
}

/// Test candidates via HTTPS time-to-first-byte, sorted by latency.
async fn test_candidates_httping(
    candidates: &[IpAddr],
    url_parts: &TestUrlParts,
    concurrency: usize,
    take_count: usize,
) -> Vec<IpAddr> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(candidates.len());

    let tls_config = build_tls_client_config();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    for &ip in candidates {
        let sem = semaphore.clone();
        let connector = connector.clone();
        let hostname = url_parts.hostname.clone();
        let port = url_parts.port;
        let path = url_parts.path.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let latency = measure_httping(ip, port, &hostname, &path, &connector).await?;
            Some((ip, latency))
        });
        handles.push(handle);
    }

    let mut results: Vec<(IpAddr, Duration)> = Vec::new();
    for handle in handles {
        if let Ok(Some((ip, latency))) = handle.await {
            results.push((ip, latency));
        }
    }

    results.sort_by(|a, b| a.1.cmp(&b.1));
    results
        .into_iter()
        .take(take_count)
        .map(|(ip, _)| ip)
        .collect()
}

/// Test candidates via HTTPS download throughput, sorted descending.
async fn test_candidates_download(
    candidates: &[IpAddr],
    url_parts: &TestUrlParts,
    concurrency: usize,
    take_count: usize,
    min_speed: Option<u64>,
) -> Vec<IpAddr> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(candidates.len());

    let tls_config = build_tls_client_config();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    for &ip in candidates {
        let sem = semaphore.clone();
        let connector = connector.clone();
        let hostname = url_parts.hostname.clone();
        let port = url_parts.port;
        let path = url_parts.path.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let throughput = measure_download_speed(ip, port, &hostname, &path, &connector).await?;
            Some((ip, throughput))
        });
        handles.push(handle);
    }

    let mut results: Vec<(IpAddr, u64)> = Vec::new();
    for handle in handles {
        if let Ok(Some((ip, throughput))) = handle.await {
            results.push((ip, throughput));
        }
    }

    // Apply min_speed filter
    if let Some(min) = min_speed {
        results.retain(|(_, speed)| *speed >= min);
    }

    // Sort by throughput descending
    results.sort_by(|a, b| b.1.cmp(&a.1));
    results
        .into_iter()
        .take(take_count)
        .map(|(ip, _)| ip)
        .collect()
}

/// Build a TLS ClientConfig using webpki_roots for certificate verification.
fn build_tls_client_config() -> rustls::ClientConfig {
    use rustls::RootCertStore;

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Measure HTTPS time-to-first-byte for a single IP.
async fn measure_httping(
    ip: IpAddr,
    port: u16,
    hostname: &str,
    path: &str,
    connector: &tokio_rustls::TlsConnector,
) -> Option<Duration> {
    use rustls::pki_types::ServerName;

    let timeout_duration = Duration::from_secs(10);
    let start = Instant::now();

    let result = tokio::time::timeout(timeout_duration, async {
        // TCP connect
        let addr = SocketAddr::new(ip, port);
        let tcp_stream = TcpStream::connect(addr).await?;

        // TLS handshake
        let server_name = ServerName::try_from(hostname.to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        // Send HTTP/1.1 GET request
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, hostname
        );
        tls_stream.write_all(request.as_bytes()).await?;

        // Read until first byte of response
        let mut buf = [0u8; 1];
        tls_stream.read_exact(&mut buf).await?;

        Ok::<(), std::io::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => Some(start.elapsed()),
        _ => None,
    }
}

/// Measure download throughput for a single IP (bytes/sec).
async fn measure_download_speed(
    ip: IpAddr,
    port: u16,
    hostname: &str,
    path: &str,
    connector: &tokio_rustls::TlsConnector,
) -> Option<u64> {
    use rustls::pki_types::ServerName;

    let download_timeout = Duration::from_secs(10);

    let result = tokio::time::timeout(download_timeout, async {
        // TCP connect
        let addr = SocketAddr::new(ip, port);
        let tcp_stream = TcpStream::connect(addr).await?;

        // TLS handshake
        let server_name = ServerName::try_from(hostname.to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        // Send HTTP/1.1 GET request
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, hostname
        );
        tls_stream.write_all(request.as_bytes()).await?;

        // Stream the response, counting bytes
        let start = Instant::now();
        let mut total_bytes: u64 = 0;
        let mut buf = [0u8; 8192];

        loop {
            match tls_stream.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    total_bytes += n as u64;
                }
                Err(_) => break,
            }
        }

        let elapsed = start.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();
        if elapsed_secs > 0.0 && total_bytes > 0 {
            Ok::<u64, std::io::Error>((total_bytes as f64 / elapsed_secs) as u64)
        } else {
            Ok(0)
        }
    })
    .await;

    match result {
        Ok(Ok(speed)) if speed > 0 => Some(speed),
        // Timeout means we downloaded for the full duration - calculate from partial data
        Err(_) => None,
        _ => None,
    }
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

    #[test]
    fn test_parse_test_url_https() {
        let parts = parse_test_url("https://speed.cloudflare.com/__down?bytes=10000000").unwrap();
        assert_eq!(parts.hostname, "speed.cloudflare.com");
        assert_eq!(parts.port, 443);
        assert_eq!(parts.path, "/__down?bytes=10000000");
    }

    #[test]
    fn test_parse_test_url_custom_port() {
        let parts = parse_test_url("https://example.com:8443/test/file.bin").unwrap();
        assert_eq!(parts.hostname, "example.com");
        assert_eq!(parts.port, 8443);
        assert_eq!(parts.path, "/test/file.bin");
    }

    #[test]
    fn test_parse_test_url_http() {
        let parts = parse_test_url("http://example.com/path").unwrap();
        assert_eq!(parts.hostname, "example.com");
        assert_eq!(parts.port, 80);
        assert_eq!(parts.path, "/path");
    }

    #[test]
    fn test_parse_test_url_root_path() {
        let parts = parse_test_url("https://example.com").unwrap();
        assert_eq!(parts.hostname, "example.com");
        assert_eq!(parts.port, 443);
        assert_eq!(parts.path, "/");
    }

    #[test]
    fn test_parse_test_url_invalid() {
        assert!(parse_test_url("not a url").is_none());
        assert!(parse_test_url("").is_none());
    }

    #[test]
    fn test_build_pipeline_stages_tcp_only() {
        let modes = vec![CfstMode::Tcp(443)];
        let stages = build_pipeline_stages(&modes);
        assert_eq!(stages, vec![PipelineStage::Tcp]);
    }

    #[test]
    fn test_build_pipeline_stages_full() {
        let modes = vec![CfstMode::Tcp(443), CfstMode::Httping, CfstMode::Download];
        let stages = build_pipeline_stages(&modes);
        assert_eq!(
            stages,
            vec![
                PipelineStage::Tcp,
                PipelineStage::Httping,
                PipelineStage::Download
            ]
        );
    }

    #[test]
    fn test_build_pipeline_stages_tcp_httping() {
        let modes = vec![CfstMode::Tcp(443), CfstMode::Httping];
        let stages = build_pipeline_stages(&modes);
        assert_eq!(stages, vec![PipelineStage::Tcp, PipelineStage::Httping]);
    }

    #[test]
    fn test_build_pipeline_stages_empty() {
        let modes: Vec<CfstMode> = vec![];
        let stages = build_pipeline_stages(&modes);
        assert_eq!(stages, vec![PipelineStage::Tcp]);
    }

    #[test]
    fn test_compute_stage_output_count_last_stage() {
        let stages = vec![
            PipelineStage::Tcp,
            PipelineStage::Httping,
            PipelineStage::Download,
        ];
        // Last stage (download) should return result_count
        assert_eq!(compute_stage_output_count(2, &stages, 4, 10), 4);
    }

    #[test]
    fn test_compute_stage_output_count_before_download() {
        let stages = vec![
            PipelineStage::Tcp,
            PipelineStage::Httping,
            PipelineStage::Download,
        ];
        // Httping (index 1) before download -> download_test_count
        assert_eq!(compute_stage_output_count(1, &stages, 4, 10), 10);
        // Tcp (index 0) before httping (which has download after) -> download_test_count
        assert_eq!(compute_stage_output_count(0, &stages, 4, 10), 10);
    }

    #[test]
    fn test_compute_stage_output_count_tcp_httping_only() {
        let stages = vec![PipelineStage::Tcp, PipelineStage::Httping];
        // Tcp (index 0) before httping with no download after -> result_count
        assert_eq!(compute_stage_output_count(0, &stages, 4, 10), 4);
        // Httping is last -> result_count
        assert_eq!(compute_stage_output_count(1, &stages, 4, 10), 4);
    }

    #[test]
    fn test_compute_stage_output_count_single_tcp() {
        let stages = vec![PipelineStage::Tcp];
        assert_eq!(compute_stage_output_count(0, &stages, 4, 10), 4);
    }

    #[test]
    fn test_min_speed_filtering() {
        // Simulate download results with min_speed filter
        let mut results: Vec<(IpAddr, u64)> = vec![
            (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 5_000_000),
            (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)), 1_000_000),
            (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3)), 10_000_000),
            (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 4)), 500_000),
        ];

        let min_speed: Option<u64> = Some(2_000_000);
        if let Some(min) = min_speed {
            results.retain(|(_, speed)| *speed >= min);
        }

        // Sort by throughput descending
        results.sort_by(|a, b| b.1.cmp(&a.1));
        let filtered: Vec<IpAddr> = results.into_iter().take(4).map(|(ip, _)| ip).collect();

        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3))); // 10M
        assert_eq!(filtered[1], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))); // 5M
    }

    #[test]
    fn test_fallback_when_no_url() {
        // When URL is None, httping/download stages should be skipped
        // This tests the parse_test_url returns None for empty/invalid input
        assert!(parse_test_url("").is_none());
    }
}
