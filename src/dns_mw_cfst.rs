//! CFST middleware: intercepts A/AAAA queries for cfst-domain entries
//! and returns cached optimized IPs from the CfstManager.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cfst_daemon::{CfstManager, QueryFamily};
use crate::dns::*;
use crate::libdns::proto::rr::{RData, RecordType};
use crate::middleware::*;

#[derive(Clone)]
pub struct CfstMiddleware {
    manager: Arc<CfstManager>,
}

impl CfstMiddleware {
    pub fn new(manager: Arc<CfstManager>) -> Self {
        Self { manager }
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

        let family = match query_type {
            RecordType::A => QueryFamily::V4,
            RecordType::AAAA => QueryFamily::V6,
            _ => return next.run(ctx, req).await,
        };

        let qname = req.query().name().to_string();

        if let Some(answer) = self.manager.lookup(&qname, family).await {
            let ttl = answer.ttl.as_secs() as u32;
            let query = req.query().original().clone();
            let name = query.name().to_owned();
            let valid_until = Instant::now() + answer.ttl;

            let records = answer.ips.iter().filter_map(|ip| match ip {
                std::net::IpAddr::V4(v4) if query_type == RecordType::A => {
                    Some(RData::A((*v4).into()))
                }
                std::net::IpAddr::V6(v6) if query_type == RecordType::AAAA => {
                    Some(RData::AAAA((*v6).into()))
                }
                _ => None,
            });

            let lookup = DnsResponse::new_with_deadline(
                query,
                records.map(|rdata| Record::from_rdata(name.clone(), ttl, rdata)),
                valid_until,
            );

            ctx.source = LookupFrom::Static;
            return Ok(lookup);
        }

        next.run(ctx, req).await
    }
}
