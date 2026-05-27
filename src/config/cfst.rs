use std::path::PathBuf;
use std::time::Duration;

use super::Domain;

/// CFST test mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfstMode {
    Tcp(u16),
    Httping,
    Download,
}

/// Global CFST configuration
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CfstConfig {
    pub ip_file: Option<PathBuf>,
    pub url: Option<String>,
    pub mode: Option<Vec<CfstMode>>,
    pub candidate_count: Option<usize>,
    pub concurrency: Option<usize>,
    pub ping_times: Option<usize>,
    pub download_test_count: Option<usize>,
    pub result_count: Option<usize>,
    pub refresh_interval: Option<Duration>,
    pub ttl: Option<u32>,
    pub min_speed: Option<u64>,
    pub serve_stale: Option<bool>,
    pub preload: Option<bool>,
}

impl CfstConfig {
    pub fn candidate_count(&self) -> usize {
        self.candidate_count.unwrap_or(1024)
    }

    pub fn concurrency(&self) -> usize {
        self.concurrency.unwrap_or(128)
    }

    pub fn ping_times(&self) -> usize {
        self.ping_times.unwrap_or(4)
    }

    pub fn download_test_count(&self) -> usize {
        self.download_test_count.unwrap_or(10)
    }

    pub fn result_count(&self) -> usize {
        self.result_count.unwrap_or(4)
    }

    pub fn refresh_interval(&self) -> Duration {
        self.refresh_interval.unwrap_or(Duration::from_secs(3600))
    }

    pub fn ttl(&self) -> u32 {
        self.ttl.unwrap_or(300)
    }

    pub fn min_speed(&self) -> Option<u64> {
        self.min_speed
    }

    pub fn serve_stale(&self) -> bool {
        self.serve_stale.unwrap_or(true)
    }

    pub fn preload(&self) -> bool {
        self.preload.unwrap_or(false)
    }
}

/// Per-domain CFST entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfstDomainEntry {
    pub domain: Domain,
    pub url: Option<String>,
    pub ip_file: Option<PathBuf>,
    pub result_count: Option<usize>,
}
