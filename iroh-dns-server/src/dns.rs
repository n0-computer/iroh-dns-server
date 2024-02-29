//! Implementation of a DNS name server for iroh node announces

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use hickory_server::{
    authority::{Catalog, MessageResponse, ZoneType},
    proto::{
        self,
        rr::{
            rdata::{self},
            RData, Record, RecordSet, RecordType, RrKey,
        },
        serialize::{binary::BinEncoder, txt::RDataParser},
    },
    resolver::Name,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryAuthority,
};

use proto::rr::LowerName;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::broadcast,
};
use tokio_util::sync::CancellationToken;
use tracing::info;

use self::node_authority::NodeAuthority;

mod node_authority;
pub use node_authority::PacketSource;
use crate::config::Config;
use crate::store::SignedPacketStore;

pub const DEFAULT_NS_TTL: u32 = 60 * 60 * 12; // 14h
pub const DEFAULT_SOA_TTL: u32 = 60 * 60 * 24 * 1; // 14d
pub const DEFAULT_A_TTL: u32 = 60 * 60; // 1h

/// DNS server settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsConfig {
    /// The port to serve a local UDP DNS server at
    pub port: u16,
    /// SOA record data for any authoritative DNS records
    pub default_soa: String,
    /// Default time to live for returned DNS records (TXT & SOA)
    pub default_ttl: u32,
    /// Domain used for serving the `_iroh_node.<nodeid>.<origin>` DNS TXT entry
    pub origin: String,
    /// Domains where CNAME records will be set on `iroh_node.<nodeid>.origin`
    pub additional_origins: Vec<String>,
    pub ipv4_addr: Option<Ipv4Addr>,
    pub ns_name: Option<String>,
}

pub async fn serve(
    config: DnsConfig,
    dns_server: DnsServer,
    token: CancellationToken,
) -> Result<()> {
    const TCP_TIMEOUT: Duration = Duration::from_millis(1000);
    let mut server = hickory_server::ServerFuture::new(dns_server);

    let ip4_addr = config
        .ipv4_addr
        .unwrap_or_else(|| Ipv4Addr::new(127, 0, 0, 1));
    let sock_addr = SocketAddrV4::new(ip4_addr, config.port);

    server.register_socket(UdpSocket::bind(sock_addr).await?);
    server.register_listener(
        TcpListener::bind(sock_addr).await?,
        TCP_TIMEOUT, // Duration::from_millis(settings.timeout_ms),
    );

    tokio::select! {
        _ = server.block_until_done() => {
            info!("Background tasks for DNS server all terminated.")
        },
        _ = token.cancelled() => {},
    };

    Ok(())
}
/// State for serving DNS
#[derive(Clone)]
pub struct DnsServer {
    pub authority: Arc<NodeAuthority>,
    /// The default SOA record used for all zones that this DNS server controls
    pub default_soa: rdata::SOA,
    pub default_ttl: u32,
    pub catalog: Arc<Catalog>,
}

impl std::fmt::Debug for DnsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsServer").finish()
    }
}

impl DnsServer {
    /// Create a DNS server given some settings, a connection to the DB for DID-by-username lookups
    /// and the server DID to serve under `_did.<origin>`.
    pub fn new(config: &DnsConfig) -> Result<Self> {
        let default_soa = RData::parse(
            RecordType::SOA,
            config.default_soa.split_ascii_whitespace(),
            None,
        )?
        .into_soa()
        .map_err(|_| anyhow!("Couldn't parse SOA: {}", config.default_soa))?;
        let store = SignedPacketStore::open_file(Config::signed_packet_store_path()?)?;
        let authority = Arc::new(Self::setup_authority(store, default_soa.clone(), config)?);

        let catalog = {
            let mut catalog = Catalog::new();
            for origin in authority.all_origins() {
                catalog.upsert(LowerName::from(origin), Box::new(Arc::clone(&authority)));
            }
            catalog
        };

        Ok(Self {
            authority,
            catalog: Arc::new(catalog),
            default_ttl: config.default_ttl,
            default_soa,
        })
    }

    /// Handle a DNS request
    pub async fn answer_request(&self, request: Request) -> Result<Bytes> {
        tracing::info!(?request, "Got DNS request");

        let (tx, mut rx) = broadcast::channel(1);
        let response_handle = Handle(tx);

        self.handle_request(&request, response_handle).await;

        tracing::debug!("Done handling request, trying to resolve response");
        Ok(rx.recv().await?)
    }

    fn setup_authority(store: SignedPacketStore, default_soa: rdata::SOA, config: &DnsConfig) -> Result<NodeAuthority> {
        let serial = default_soa.serial();
        let origin = Name::parse(&config.origin, Some(&Name::root()))?;
        let additional_origins = config
            .additional_origins
            .iter()
            .map(|o| {
                Name::parse(o, Some(&Name::root())).map_err(|e| anyhow!("invalid origin {o}: {e}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let all_origins = Some(origin.clone())
            .into_iter()
            .chain(additional_origins.clone())
            .collect::<Vec<_>>();

        let mut records = BTreeMap::new();
        push_record(
            &mut records,
            serial,
            Record::from_rdata(origin.clone(), DEFAULT_SOA_TTL, RData::SOA(default_soa)),
        );
        if let Some(addr) = config.ipv4_addr {
            for name in &all_origins {
                push_record(
                    &mut records,
                    serial,
                    Record::from_rdata(name.clone(), DEFAULT_A_TTL, RData::A(addr.into())),
                );
            }
        }

        if let Some(ns_name) = &config.ns_name {
            let ns = Name::parse(ns_name, Some(&Name::root()))?;
            for name in &all_origins {
                push_record(
                    &mut records,
                    serial,
                    Record::from_rdata(
                        name.clone(),
                        DEFAULT_NS_TTL,
                        RData::NS(rdata::NS(ns.clone())),
                    ),
                );
            }
        }
        let static_authority =
            InMemoryAuthority::new(origin.clone(), records, ZoneType::Primary, false)
                .map_err(|e| anyhow!(e))?;

        let authority = NodeAuthority::new(store, static_authority, origin, additional_origins, serial)?;

        Ok(authority)
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsServer {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        self.catalog.handle_request(request, response_handle).await
    }
}

/// A handle to the channel over which the response to a DNS request will be sent
#[derive(Debug, Clone)]
pub struct Handle(pub broadcast::Sender<Bytes>);

#[async_trait]
impl ResponseHandler for Handle {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let mut bytes = Vec::with_capacity(512);
        let info = {
            let mut encoder = BinEncoder::new(&mut bytes);
            response.destructive_emit(&mut encoder)?
        };

        let bytes = Bytes::from(bytes);
        self.0.send(bytes).unwrap();

        Ok(info)
    }
}

fn push_record(records: &mut BTreeMap<RrKey, RecordSet>, serial: u32, record: Record) {
    let key = RrKey::new(record.name().clone().into(), record.record_type());
    let mut record_set = RecordSet::new(record.name(), record.record_type(), serial);
    record_set.insert(record, serial);
    records.insert(key, record_set);
}
