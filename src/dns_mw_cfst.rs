use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cfst::CfstManager;
use crate::config::CfstConfig;
use crate::dns::*;
use crate::libdns::proto::rr::{RData, RecordType};
use crate::log::debug;
use crate::middleware::*;

pub struct CfstMiddleware {
    manager: Arc<CfstManager>,
    config: Arc<CfstConfig>,
}

impl CfstMiddleware {
    pub fn new(manager: Arc<CfstManager>, config: Arc<CfstConfig>) -> Self {
        Self { manager, config }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for CfstMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let query_type = req.query().query_type();
        let query_name = req.query().name().to_owned();

        // Only intercept A and AAAA queries
        if !matches!(query_type, RecordType::A | RecordType::AAAA) {
            return next.run(ctx, req).await;
        }

        // Check if this domain is managed by cfst
        if !self.manager.has_domain(&query_name) {
            return next.run(ctx, req).await;
        }

        // Find the matching cache key
        let cache_name = match self.manager.find_matching_name(&query_name) {
            Some(name) => name.clone(),
            None => return next.run(ctx, req).await,
        };

        // Get cached results
        let results = match self.manager.get_results(&cache_name).await {
            Some(r) => r,
            None => {
                // No results yet; if serve_stale is false, fall through
                if !self.config.serve_stale() {
                    return next.run(ctx, req).await;
                }
                return next.run(ctx, req).await;
            }
        };

        // Determine TTL
        let ttl = if results.stale {
            30u32
        } else {
            self.config.ttl()
        };

        match query_type {
            RecordType::A => {
                if !results.has_ipv4() {
                    return next.run(ctx, req).await;
                }

                let query = req.query().original().clone();
                let name = query.name().to_owned();
                let valid_until = Instant::now() + Duration::from_secs(u64::from(ttl));

                let records: Vec<Record> = results
                    .ipv4
                    .iter()
                    .map(|ip| Record::from_rdata(name.clone(), ttl, RData::A((*ip).into())))
                    .collect();

                debug!(
                    "cfst answer domain={} qtype={:?} ips={} ttl={} stale={}",
                    name.to_string().trim_end_matches('.'),
                    query_type,
                    records.len(),
                    ttl,
                    results.stale
                );

                ctx.source = LookupFrom::Static;
                Ok(DnsResponse::new_with_deadline(query, records, valid_until))
            }
            RecordType::AAAA => {
                if !results.has_ipv6() {
                    return next.run(ctx, req).await;
                }

                let query = req.query().original().clone();
                let name = query.name().to_owned();
                let valid_until = Instant::now() + Duration::from_secs(u64::from(ttl));

                let records: Vec<Record> = results
                    .ipv6
                    .iter()
                    .map(|ip| Record::from_rdata(name.clone(), ttl, RData::AAAA((*ip).into())))
                    .collect();

                debug!(
                    "cfst answer domain={} qtype={:?} ips={} ttl={} stale={}",
                    name.to_string().trim_end_matches('.'),
                    query_type,
                    records.len(),
                    ttl,
                    results.stale
                );

                ctx.source = LookupFrom::Static;
                Ok(DnsResponse::new_with_deadline(query, records, valid_until))
            }
            _ => next.run(ctx, req).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfst::CfstResults;
    use crate::dns_conf::RuntimeConfig;
    use crate::dns_mw::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Helper to create a CfstManager with pre-populated results
    async fn create_test_manager(
        domain: &str,
        ipv4: Vec<Ipv4Addr>,
        ipv6: Vec<Ipv6Addr>,
    ) -> Arc<CfstManager> {
        use crate::config::WildcardName;
        use crate::config::{CfstDomainEntry, Domain};

        let name: Name = domain.parse().unwrap();
        let wildcard_name = WildcardName::Default(name.clone());
        let entry = CfstDomainEntry {
            domain: Domain::Name(wildcard_name),
            url: None,
            ip_file: None,
            result_count: None,
        };

        let config = CfstConfig::default();
        let manager = CfstManager::new(config, vec![entry]);

        // Pre-populate results
        let results = CfstResults {
            ipv4,
            ipv6,
            updated_at: Instant::now(),
            stale: false,
        };

        let mut map = manager.results.write().await;
        map.insert(name, results);
        drop(map);

        manager
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_cfst_middleware_returns_cached_ipv4() {
        let manager = create_test_manager(
            "cdn.example.com",
            vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()],
            vec![],
        )
        .await;
        let config = Arc::new(CfstConfig::default());
        let middleware = CfstMiddleware::new(manager, config);

        let cfg = RuntimeConfig::builder().build().unwrap();

        let mock = DnsMockMiddleware::mock(middleware).build(cfg);

        let result = mock
            .lookup_rdata("cdn.example.com", RecordType::A)
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains(&RData::A("1.2.3.4".parse().unwrap())));
        assert!(result.contains(&RData::A("5.6.7.8".parse().unwrap())));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_cfst_middleware_returns_cached_ipv6() {
        let manager = create_test_manager(
            "cdn.example.com",
            vec![],
            vec!["2001:db8::1".parse().unwrap()],
        )
        .await;
        let config = Arc::new(CfstConfig::default());
        let middleware = CfstMiddleware::new(manager, config);

        let cfg = RuntimeConfig::builder().build().unwrap();

        let mock = DnsMockMiddleware::mock(middleware).build(cfg);

        let result = mock
            .lookup_rdata("cdn.example.com", RecordType::AAAA)
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains(&RData::AAAA("2001:db8::1".parse().unwrap())));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_cfst_middleware_passthrough_non_cfst_domain() {
        let manager =
            create_test_manager("cdn.example.com", vec!["1.2.3.4".parse().unwrap()], vec![]).await;
        let config = Arc::new(CfstConfig::default());
        let middleware = CfstMiddleware::new(manager, config);

        let cfg = RuntimeConfig::builder().build().unwrap();

        let mock = DnsMockMiddleware::mock(middleware)
            .with_a_record("other.example.com", "9.9.9.9".parse().unwrap())
            .build(cfg);

        let result = mock
            .lookup_rdata("other.example.com", RecordType::A)
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], RData::A("9.9.9.9".parse().unwrap()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_cfst_middleware_passthrough_when_no_ipv4_results() {
        let manager = create_test_manager("cdn.example.com", vec![], vec![]).await;
        let config = Arc::new(CfstConfig::default());
        let middleware = CfstMiddleware::new(manager, config);

        let cfg = RuntimeConfig::builder().build().unwrap();

        let mock = DnsMockMiddleware::mock(middleware)
            .with_a_record("cdn.example.com", "9.9.9.9".parse().unwrap())
            .build(cfg);

        let result = mock
            .lookup_rdata("cdn.example.com", RecordType::A)
            .await
            .unwrap();

        // Should fall through because results has no IPv4
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], RData::A("9.9.9.9".parse().unwrap()));
    }
}
