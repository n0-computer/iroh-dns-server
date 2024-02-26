//! Implementation of a DNS name server for iroh node announces

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use hickory_server::{
    authority::{Authority, AuthorityObject, Catalog, MessageResponse, ZoneType},
    proto::{
        self,
        rr::{
            rdata::{self, TXT},
            RData, Record, RecordSet, RecordType, RrKey,
        },
        serialize::{binary::BinEncoder, txt::RDataParser},
    },
    resolver::{config::NameServerConfigGroup, Name},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::{
        forwarder::{ForwardAuthority, ForwardConfig},
        in_memory::InMemoryAuthority,
    },
};
use iroh_net::NodeId;
use proto::rr::LowerName;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::broadcast,
};
use tokio_util::sync::CancellationToken;
use tracing::info;
use url::Url;

use self::authority::IrohAuthority;

mod authority;

pub const IROH_ROOT_ZONE: &'static str = "iroh";

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
    /// The authority that handles the server's main `_did` DNS TXT record lookups
    pub authority: Arc<IrohAuthority>,
    // /// The authority that handles all user `_did` DNS TXT record lookups
    // pub user_did_authority: Arc<UserDidsAuthority>,
    /// The catch-all authority that forwards requests to secondary nameservers
    pub forwarder: Arc<ForwardAuthority>,
    /// The authority handling the `.test` TLD for mocking in tests.
    /// The idea is that this would *normally* resolve in the
    /// `ForwardAuthority` in the real world, but we don't want to
    /// depend on that functionality in unit tests.
    pub test_authority: Arc<InMemoryAuthority>,
    /// The default SOA record used for all zones that this DNS server controls
    pub default_soa: rdata::SOA,
    pub default_ttl: u32,

    pub catalog: Arc<Catalog>,
}

impl std::fmt::Debug for DnsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsState")
            .field("server_did_authority", &"InMemoryAuthority {{ .. }}")
            // .field("user_did_authority", &self.user_did_authority)
            .field("forwarder", &"ForwardAuthority {{ .. }}")
            .finish()
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

        let origin = Name::parse(&config.origin, Some(&Name::root()))?;
        let additional_origins = config
            .additional_origins
            .iter()
            .map(|o| {
                Name::parse(&o, Some(&Name::root())).map_err(|e| anyhow!("invalid origin {o}: {e}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let all_origins = Some(origin.clone())
            .into_iter()
            .chain(additional_origins.clone().into_iter())
            .map(|n| LowerName::from(n));

        let authority = Arc::new(Self::setup_authority(
            origin,
            default_soa.clone(),
            additional_origins,
            config.ipv4_addr,
        )?);
        let forwarder = Arc::new(Self::setup_forwarder()?);
        let test_authority = Arc::new(Self::setup_test_authority(default_soa.clone())?);

        let catalog = {
            let mut catalog = Catalog::new();
            for origin in all_origins {
                catalog.upsert(origin, Box::new(Arc::clone(&authority)));
            }
            catalog.upsert(
                test_authority.origin().clone(),
                Box::new(Arc::clone(&test_authority)),
            );
            catalog.upsert(Name::root().into(), Box::new(Arc::clone(&forwarder)));
            catalog
        };

        Ok(Self {
            authority,
            test_authority,
            forwarder,
            catalog: Arc::new(catalog),
            default_ttl: config.default_ttl,
            default_soa,
        })
    }

    /// Handle a DNS request
    pub async fn answer_request(&self, request: Request) -> Result<Bytes> {
        tracing::info!(?request, "Got DNS request");
        println!("request {request:#?}");

        let (tx, mut rx) = broadcast::channel(1);
        let response_handle = Handle(tx);

        self.handle_request(&request, response_handle).await;

        tracing::debug!("Done handling request, trying to resolve response");
        Ok(rx.recv().await?)
    }

    fn setup_authority(
        origin: Name,
        default_soa: rdata::SOA,
        additional_origins: Vec<Name>,
        ipv4_addr: Option<Ipv4Addr>,
    ) -> Result<IrohAuthority> {
        // // let origin = Name::parse(&config.origin, Some(&Name::root()))?;
        // let origin = Name::parse(IROH_ROOT_ZONE, Some(&Name::root()))?;
        let serial = default_soa.serial();
        let mut records = BTreeMap::from([(
            RrKey::new(origin.clone().into(), RecordType::SOA),
            record_set(
                &origin,
                RecordType::SOA,
                serial,
                Record::from_rdata(origin.clone(), 1209600, RData::SOA(default_soa)),
            ),
        )]);
        if let Some(addr) = ipv4_addr {
            let key = RrKey::new(origin.clone().into(), RecordType::A);
            let record_set = record_set(
                &origin,
                RecordType::A,
                serial,
                Record::from_rdata(origin.clone(), 900, RData::A(addr.into())),
            );
            records.insert(key, record_set);
        }
        let authority = InMemoryAuthority::new(origin.clone(), records, ZoneType::Primary, false)
            .map_err(|e| anyhow!(e))?;

        let authority = IrohAuthority {
            inner: authority,
            additional_origins,
        };

        Ok(authority)
    }

    fn setup_forwarder() -> Result<ForwardAuthority> {
        let config = ForwardConfig {
            name_servers: NameServerConfigGroup::cloudflare(),
            options: None,
        };

        let forwarder = ForwardAuthority::try_from_config(Name::root(), ZoneType::Forward, &config)
            .map_err(|e| anyhow!(e))?;

        Ok(forwarder)
    }

    fn setup_test_authority(default_soa: rdata::SOA) -> Result<InMemoryAuthority> {
        let origin = Name::parse("test", Some(&Name::root()))?;
        let serial = default_soa.serial();
        InMemoryAuthority::new(
            origin.clone(),
            BTreeMap::from([(
                RrKey::new(origin.clone().into(), RecordType::SOA),
                record_set(
                    &origin,
                    RecordType::SOA,
                    serial,
                    Record::from_rdata(origin.clone(), 1209600, RData::SOA(default_soa)),
                ),
            )]),
            ZoneType::Primary,
            false,
        )
        .map_err(|e| anyhow!(e))
    }

    /// Add a DNS record under `<subdomain>.test.`
    pub async fn set_test_record(
        &self,
        subdomain: &str,
        record_type: RecordType,
        rset: RecordSet,
    ) -> Result<()> {
        let name = Name::parse(subdomain, Some(&self.test_authority.origin().into()))?;
        let mut records = self.test_authority.records_mut().await;
        records.insert(RrKey::new(name.into(), record_type), Arc::new(rset));
        Ok(())
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

/// Create a record set with a single record inside
pub(crate) fn record_set(
    name: &Name,
    record_type: RecordType,
    serial: u32,
    record: Record,
) -> RecordSet {
    let mut record_set = RecordSet::new(name, record_type, serial);
    record_set.insert(record, serial);
    record_set
}
