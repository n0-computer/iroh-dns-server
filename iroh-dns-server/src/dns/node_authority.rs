use std::{
    collections::{btree_map, BTreeMap},
    fmt,
    sync::Arc,
};

use anyhow::{bail, Result};
use async_trait::async_trait;
use hickory_proto::{
    op::ResponseCode,
    rr::{LowerName, Name, RecordSet, RecordType, RrKey},
};
use hickory_server::{
    authority::{
        AuthLookup, Authority, LookupError, LookupOptions, LookupRecords, MessageRequest,
        UpdateResult, ZoneType,
    },
    server::RequestInfo,
    store::in_memory::InMemoryAuthority,
};

use iroh_metrics::inc;
use parking_lot::RwLock;
use pkarr::SignedPacket;
use tracing::{debug, trace};

use crate::util::{record_set_append_origin, signed_packet_to_hickory_records_without_origin};
use crate::{metrics::Metrics, store::SignedPacketStore};

pub enum PacketSource {
    PkarrPublish,
    Mainline,
}

pub type PublicKeyBytes = [u8; 32];

#[derive(derive_more::Debug)]
pub struct NodeAuthority {
    serial: u32,
    primary_origin: LowerName,
    all_origins: Vec<Name>,

    store: SignedPacketStore,
    #[debug("InMemoryAuthority")]
    static_authority: InMemoryAuthority,
    zones: RwLock<BTreeMap<PublicKeyBytes, PkarrZone>>,
}

#[derive(Debug)]
struct PkarrZone {
    timestamp: u64,
    records: BTreeMap<RrKey, Arc<RecordSet>>,
}

impl PkarrZone {
    fn from_signed_packet(signed_packet: &SignedPacket) -> Result<Self> {
        let (_label, records) =
            signed_packet_to_hickory_records_without_origin(signed_packet, |_| true)?;
        Ok(Self {
            records,
            timestamp: *signed_packet.timestamp(),
        })
    }

    fn older_than(&self, signed_packet: &SignedPacket) -> bool {
        *signed_packet.timestamp() > self.timestamp
    }

    fn records(&self) -> &BTreeMap<RrKey, Arc<RecordSet>> {
        &self.records
    }
}

impl NodeAuthority {
    pub fn new(
        store: SignedPacketStore,
        static_authority: InMemoryAuthority,
        primary_origin: Name,
        additional_origins: Vec<Name>,
        serial: u32,
    ) -> Result<Self> {
        let origins = {
            let mut o = Vec::with_capacity(additional_origins.len());
            o.push(primary_origin.clone());
            o.extend_from_slice(&additional_origins);
            o
        };
        let this = Self {
            static_authority,
            primary_origin: primary_origin.into(),
            all_origins: origins,
            serial,
            store,
            zones: Default::default(),
        };
        for packet in this.store.iter()? {
            let packet = packet?;
            this.upsert_pkarr_zone(&packet)?;
        }
        Ok(this)
    }
    pub fn all_origins(&self) -> impl Iterator<Item = &Name> {
        self.all_origins.iter()
    }

    pub fn origin_is_allowed(&self, origin: &Name) -> bool {
        self.all_origins.contains(origin)
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    // todo: less clones
    pub fn resolve_pkarr(
        &self,
        public_key: &pkarr::PublicKey,
        name: &Name,
        record_type: RecordType,
    ) -> Option<Arc<RecordSet>> {
        let key = RrKey::new(name.into(), record_type);
        self.zones
            .read()
            .get(&public_key.to_bytes())
            .and_then(|zone| zone.records().get(&key))
            .map(Arc::clone)
    }

    pub fn upsert_pkarr(&self, signed_packet: SignedPacket, _source: PacketSource) -> Result<bool> {
        let updated = match self.upsert_pkarr_zone(&signed_packet) {
            Ok(updated) => updated,
            Err(err) => {
                inc!(Metrics, pkarr_publish_error);
                return Err(err);
            }
        };
        if updated {
            self.store.upsert(signed_packet)?;
            inc!(Metrics, pkarr_publish_update);
        } else {
            inc!(Metrics, pkarr_publish_noop);
        }
        Ok(updated)
    }

    pub fn store(&self) -> &SignedPacketStore {
        &self.store
    }

    fn upsert_pkarr_zone(&self, signed_packet: &SignedPacket) -> Result<bool> {
        let key = signed_packet.public_key().to_bytes();
        let mut updated = false;
        match self.zones.write().entry(key) {
            btree_map::Entry::Vacant(e) => {
                e.insert(PkarrZone::from_signed_packet(signed_packet)?);
                updated = true;
            }
            btree_map::Entry::Occupied(mut e) => {
                if e.get().older_than(signed_packet) {
                    e.insert(PkarrZone::from_signed_packet(signed_packet)?);
                    updated = true;
                }
            }
        }
        Ok(updated)
    }
}

#[async_trait]
impl Authority for NodeAuthority {
    type Lookup = AuthLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        &self.primary_origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        match record_type {
            RecordType::SOA | RecordType::NS => {
                self.static_authority
                    .lookup(name, record_type, lookup_options)
                    .await
            }
            _ => {
                let name2: Name = name.into();
                match split_and_parse_pkarr(&name2, &self.all_origins) {
                    Err(err) => {
                        debug!("name {name2} does not match pkarr: {err}");
                        self.static_authority
                            .lookup(name, record_type, lookup_options)
                            .await
                    }
                    Ok((name, pkey, origin)) => {
                        debug!("name {name2} resolved to ({name}) ({pkey}) ({origin})");
                        match self.resolve_pkarr(&pkey, &name, record_type) {
                            Some(pkarr_set) => {
                                let new_origin = Name::parse(&pkey.to_z32(), Some(&origin))
                                    .map_err(err_refused)?;
                                let record_set = record_set_append_origin(
                                    &pkarr_set,
                                    &new_origin,
                                    self.serial(),
                                )
                                .map_err(err_refused)?;
                                let records =
                                    LookupRecords::new(lookup_options, Arc::new(record_set));
                                let answers = AuthLookup::answers(records, None);
                                Ok(answers)
                            }
                            None => Err(err_nx_domain("not found")),
                        }
                    }
                }
            }
        }
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        debug!("searching NodeAuthority for: {}", request_info.query);
        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();
        match record_type {
            RecordType::SOA => {
                self.static_authority
                    .lookup(self.origin(), record_type, lookup_options)
                    .await
            }
            RecordType::AXFR => Err(LookupError::from(ResponseCode::Refused)),
            _ => self.lookup(lookup_name, record_type, lookup_options).await,
        }
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Ok(AuthLookup::default())
    }
}

fn split_and_parse_pkarr(
    name: &Name,
    allowed_origins: &[Name],
) -> Result<(Name, pkarr::PublicKey, Name)> {
    trace!("resolve {name}");
    for origin in allowed_origins.iter() {
        trace!("try {origin}");
        if !origin.zone_of(name) {
            continue;
        }
        if name.num_labels() < origin.num_labels() + 1 {
            bail!("invalid name");
        }
        trace!("parse {origin}");
        let labels = name.iter().rev();
        let mut labels_without_origin = labels.skip(origin.num_labels() as usize);
        let pkey_label = labels_without_origin.next().expect("length checked above");
        let pkey = pkarr::PublicKey::try_from(std::str::from_utf8(pkey_label)?)?;
        let remaining_name = Name::from_labels(labels_without_origin)?;
        return Ok((remaining_name, pkey, origin.clone()));
    }
    bail!("name does not match any origin");
}

fn err_refused(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (refused): {e:?}");
    LookupError::from(ResponseCode::Refused)
}
fn err_nx_domain(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (nxdomain): {e:?}");
    LookupError::from(ResponseCode::NXDomain)
}
