//! CloudflareSpeedTest-style IP optimizer.
//!
//! Pipeline:
//! - sample candidate addresses from one or more CIDR ranges;
//! - run TCP connect latency checks;
//! - optionally verify HTTP/HTTPS latency against a URL;
//! - optionally run a bounded download throughput test;
//! - sort by throughput descending, then latency ascending.

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use futures::{stream, StreamExt};
use ipnet::IpNet;
use rand::{rng, Rng};
use reqwest::header::HeaderMap;
use reqwest::{Client, Url};
use tokio::net::TcpStream;
use tokio::time;

#[derive(Clone, Debug)]
pub struct CfstConfig {
    pub ranges: Vec<IpNet>,
    pub candidate_count: usize,
    pub concurrency: usize,
    pub tcp_port: u16,
    pub ping_times: usize,
    pub connect_timeout: Duration,
    pub download_test_count: usize,
    pub url: Option<Url>,
    pub httping: bool,
    pub download: bool,
    pub download_timeout: Duration,
    pub min_download_speed: u64,
    pub result_count: usize,
}

impl Default for CfstConfig {
    fn default() -> Self {
        Self {
            ranges: Vec::new(),
            candidate_count: 1024,
            concurrency: 128,
            tcp_port: 443,
            ping_times: 4,
            connect_timeout: Duration::from_secs(1),
            download_test_count: 10,
            url: None,
            httping: false,
            download: false,
            download_timeout: Duration::from_secs(10),
            min_download_speed: 0,
            result_count: 4,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CfstResult {
    pub ip: IpAddr,
    pub tcp_port: u16,
    pub sent: usize,
    pub received: usize,
    pub avg_latency: Duration,
    pub http_latency: Option<Duration>,
    pub download_speed: Option<u64>,
    pub colo: Option<String>,
}

impl CfstResult {
    pub fn download_speed_mbps(&self) -> Option<f64> {
        self.download_speed
            .map(|bps| bps as f64 * 8.0 / 1_000_000.0)
    }
}

pub async fn run_cfst(config: CfstConfig) -> Result<Vec<CfstResult>> {
    if config.ranges.is_empty() {
        bail!("cfst requires at least one IP range");
    }
    if config.candidate_count == 0 || config.result_count == 0 {
        return Ok(Vec::new());
    }
    if (config.httping || config.download) && config.url.is_none() {
        bail!("cfst httping/download requires a URL");
    }

    let candidates = sample_candidates(&config.ranges, config.candidate_count);
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let cfg = Arc::new(config);

    // TCP latency phase
    let mut latency_results: Vec<CfstResult> = stream::iter(candidates)
        .map(|ip| {
            let cfg = Arc::clone(&cfg);
            async move { tcp_latency(ip, &cfg).await }
        })
        .buffer_unordered(cfg.concurrency.max(1))
        .filter_map(|r| async move { r })
        .collect()
        .await;

    latency_results.sort_by(compare_latency);

    // HTTP HEAD phase
    if cfg.httping {
        let url = cfg.url.clone().expect("checked above");
        latency_results = stream::iter(latency_results)
            .map(|mut result| {
                let cfg = Arc::clone(&cfg);
                let url = url.clone();
                async move {
                    if let Ok((latency, colo)) =
                        http_head_latency(result.ip, cfg.tcp_port, &url, &cfg).await
                    {
                        result.http_latency = Some(latency);
                        if colo.is_some() {
                            result.colo = colo;
                        }
                        Some(result)
                    } else {
                        None
                    }
                }
            })
            .buffer_unordered(cfg.concurrency.max(1))
            .filter_map(|r| async move { r })
            .collect()
            .await;

        latency_results.sort_by(compare_latency);
    }

    // Download phase
    if cfg.download {
        let url = cfg.url.clone().expect("checked above");
        let selected: Vec<CfstResult> = latency_results
            .into_iter()
            .take(cfg.download_test_count.max(cfg.result_count))
            .collect();

        let mut download_results: Vec<CfstResult> = stream::iter(selected)
            .map(|mut result| {
                let cfg = Arc::clone(&cfg);
                let url = url.clone();
                async move {
                    match download_speed(result.ip, cfg.tcp_port, &url, &cfg).await {
                        Ok((speed, colo)) => {
                            if cfg.min_download_speed > 0 && speed < cfg.min_download_speed {
                                return None;
                            }
                            result.download_speed = Some(speed);
                            if colo.is_some() {
                                result.colo = colo;
                            }
                            Some(result)
                        }
                        Err(_) => None,
                    }
                }
            })
            .buffer_unordered(cfg.concurrency.min(cfg.download_test_count).max(1))
            .filter_map(|r| async move { r })
            .collect()
            .await;

        download_results.sort_by(compare_download_then_latency);
        download_results.truncate(cfg.result_count);
        return Ok(download_results);
    }

    latency_results.truncate(cfg.result_count);
    Ok(latency_results)
}

pub fn parse_ranges<I, S>(items: I) -> Result<Vec<IpNet>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut ranges = Vec::new();
    for item in items {
        let raw = item.as_ref().trim();
        if raw.is_empty() || raw.starts_with('#') {
            continue;
        }
        if let Ok(net) = IpNet::from_str(raw) {
            ranges.push(net);
            continue;
        }
        if let Ok(ip) = IpAddr::from_str(raw) {
            ranges.push(match ip {
                IpAddr::V4(v4) => IpNet::new(IpAddr::V4(v4), 32)?,
                IpAddr::V6(v6) => IpNet::new(IpAddr::V6(v6), 128)?,
            });
            continue;
        }
        bail!("invalid cfst IP range: {raw}");
    }
    Ok(ranges)
}

pub fn render_address_rules(domain: &str, results: &[CfstResult]) -> String {
    let mut out = String::new();
    let domain = domain.trim_matches('/');
    for item in results {
        out.push_str(&format!("address /{domain}/{}\n", item.ip));
    }
    out
}

fn sample_candidates(ranges: &[IpNet], count: usize) -> Vec<IpAddr> {
    let mut rng = rng();
    let mut out = Vec::with_capacity(count);
    if ranges.is_empty() {
        return out;
    }
    let mut index = 0usize;
    while out.len() < count {
        let net = &ranges[index % ranges.len()];
        let ip = sample_ip(net, &mut rng);
        if !out.contains(&ip) {
            out.push(ip);
        }
        index += 1;
        if index > count.saturating_mul(ranges.len()).saturating_mul(8) {
            break;
        }
    }
    out
}

fn sample_ip<R: Rng + ?Sized>(net: &IpNet, rng: &mut R) -> IpAddr {
    match net {
        IpNet::V4(v4) => {
            let base = u32::from(v4.network());
            let host_bits = 32u8.saturating_sub(v4.prefix_len());
            let host_mask = if host_bits == 32 {
                u32::MAX
            } else if host_bits == 0 {
                0
            } else {
                (1u32 << host_bits) - 1
            };
            let offset = rng.random::<u32>() & host_mask;
            IpAddr::V4(Ipv4Addr::from(base | offset))
        }
        IpNet::V6(v6) => {
            let base = u128::from(v6.network());
            let host_bits = 128u8.saturating_sub(v6.prefix_len());
            let host_mask = if host_bits == 128 {
                u128::MAX
            } else if host_bits == 0 {
                0
            } else {
                (1u128 << host_bits) - 1
            };
            let offset = rng.random::<u128>() & host_mask;
            IpAddr::V6(Ipv6Addr::from(base | offset))
        }
    }
}

async fn tcp_latency(ip: IpAddr, cfg: &CfstConfig) -> Option<CfstResult> {
    let addr = SocketAddr::new(ip, cfg.tcp_port);
    let mut received = 0usize;
    let mut total = Duration::ZERO;
    for _ in 0..cfg.ping_times.max(1) {
        let start = Instant::now();
        match time::timeout(cfg.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                received += 1;
                total += start.elapsed();
            }
            _ => {}
        }
    }
    if received == 0 {
        return None;
    }
    Some(CfstResult {
        ip,
        tcp_port: cfg.tcp_port,
        sent: cfg.ping_times.max(1),
        received,
        avg_latency: total / received as u32,
        http_latency: None,
        download_speed: None,
        colo: None,
    })
}

async fn http_head_latency(
    ip: IpAddr,
    port: u16,
    url: &Url,
    cfg: &CfstConfig,
) -> Result<(Duration, Option<String>)> {
    let client = client_resolving_to(ip, port, url)?;
    let mut total = Duration::ZERO;
    let mut received = 0usize;
    let mut last_colo = None;
    for _ in 0..cfg.ping_times.max(1) {
        let start = Instant::now();
        let response = time::timeout(cfg.connect_timeout * 3, client.head(url.clone()).send())
            .await
            .context("httping timeout")??;
        if !is_valid_httping_status(response.status().as_u16()) {
            bail!("unexpected httping status: {}", response.status());
        }
        total += start.elapsed();
        received += 1;
        if last_colo.is_none() {
            last_colo = extract_colo(response.headers());
        }
    }
    if received == 0 {
        bail!("no httping response");
    }
    Ok((total / received as u32, last_colo))
}

async fn download_speed(
    ip: IpAddr,
    port: u16,
    url: &Url,
    cfg: &CfstConfig,
) -> Result<(u64, Option<String>)> {
    let client = client_resolving_to(ip, port, url)?;
    let started = Instant::now();
    let mut response = time::timeout(cfg.connect_timeout * 5, client.get(url.clone()).send())
        .await
        .context("download request timeout")??;

    if !response.status().is_success() {
        bail!("unexpected download status: {}", response.status());
    }

    let colo = extract_colo(response.headers());
    let mut bytes = 0u64;
    loop {
        if started.elapsed() >= cfg.download_timeout {
            break;
        }
        let remaining = cfg
            .download_timeout
            .checked_sub(started.elapsed())
            .unwrap_or(Duration::from_millis(1));
        match time::timeout(remaining, response.chunk()).await {
            Ok(Ok(Some(chunk))) => bytes += chunk.len() as u64,
            Ok(Ok(None)) => break,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => break,
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    if bytes == 0 || elapsed <= 0.0 {
        bail!("no download bytes received");
    }
    Ok(((bytes as f64 / elapsed) as u64, colo))
}

fn client_resolving_to(ip: IpAddr, port: u16, url: &Url) -> Result<Client> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("cfst URL must contain a host"))?
        .to_string();
    let effective_port = url.port_or_known_default().unwrap_or(port);
    let addr = SocketAddr::new(ip, effective_port);
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, addr)
        .danger_accept_invalid_certs(false)
        .build()
        .context("build cfst HTTP client")
}

fn is_valid_httping_status(status: u16) -> bool {
    matches!(status, 200 | 301 | 302)
}

fn extract_colo(headers: &HeaderMap) -> Option<String> {
    let server = header_value(headers, "server").unwrap_or_default();
    if server.eq_ignore_ascii_case("cloudflare") {
        if let Some(ray) = header_value(headers, "cf-ray") {
            if let Some(suffix) = ray.rsplit('-').next() {
                let colo: String = suffix
                    .chars()
                    .take_while(|c| c.is_ascii_alphabetic())
                    .collect::<String>()
                    .to_uppercase();
                if colo.len() == 3 {
                    return Some(colo);
                }
            }
        }
    }
    for name in [
        "x-77-pop",
        "x-bunny-pop",
        "x-amz-cf-pop",
        "x-served-by",
        "x-gcore-node",
    ] {
        if let Some(value) = header_value(headers, name) {
            if let Some(colo) = first_three_letter_token(&value) {
                return Some(colo);
            }
        }
    }
    None
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
}

fn first_three_letter_token(value: &str) -> Option<String> {
    let upper = value.to_uppercase();
    for token in upper.split(|c: char| !c.is_ascii_alphabetic()) {
        if token.len() >= 3 {
            return Some(token.chars().take(3).collect());
        }
    }
    None
}

fn compare_latency(a: &CfstResult, b: &CfstResult) -> Ordering {
    let a_lat = a.http_latency.unwrap_or(a.avg_latency);
    let b_lat = b.http_latency.unwrap_or(b.avg_latency);
    a_lat
        .cmp(&b_lat)
        .then_with(|| b.received.cmp(&a.received))
        .then_with(|| a.ip.cmp(&b.ip))
}

fn compare_download_then_latency(a: &CfstResult, b: &CfstResult) -> Ordering {
    b.download_speed
        .unwrap_or(0)
        .cmp(&a.download_speed.unwrap_or(0))
        .then_with(|| compare_latency(a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ips_as_host_routes() {
        let ranges = parse_ranges(["1.1.1.1", "2606:4700:4700::1111"]).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].prefix_len(), 32);
        assert_eq!(ranges[1].prefix_len(), 128);
    }

    #[test]
    fn samples_inside_range() {
        let range: IpNet = "192.0.2.0/24".parse().unwrap();
        for _ in 0..100 {
            let ip = sample_ip(&range, &mut rng());
            assert!(range.contains(&ip));
        }
    }

    #[test]
    fn renders_address_rules() {
        let item = CfstResult {
            ip: "1.1.1.1".parse().unwrap(),
            tcp_port: 443,
            sent: 4,
            received: 4,
            avg_latency: Duration::from_millis(10),
            http_latency: None,
            download_speed: None,
            colo: Some("PAR".to_string()),
        };
        assert_eq!(
            render_address_rules("example.com", &[item]),
            "address /example.com/1.1.1.1\n"
        );
    }
}
