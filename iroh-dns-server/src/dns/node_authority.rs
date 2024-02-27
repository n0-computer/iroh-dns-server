use std::{
    borrow::Borrow,
    collections::{hash_map, HashMap},
    sync::Arc,
};

use anyhow::{bail, Result};
use async_trait::async_trait;
use hickory_proto::{
    op::ResponseCode,
    rr::{LowerName, Name, Record, RecordType},
};
use hickory_server::{
    authority::{
        AuthLookup, Authority, LookupError, LookupOptions, LookupRecords, MessageRequest,
        UpdateResult, ZoneType,
    },
    server::RequestInfo,
    store::in_memory::InMemoryAuthority,
};
use iroh_dns::packet::{NodeAnnounce, IROH_NODE_TXT_LABEL};
use iroh_net::NodeId;
use pkarr::SignedPacket;
use tracing::debug;

use super::record_set;

struct NodeState {
    signed_packet: SignedPacket,
    announce: NodeAnnounce,
}

impl NodeState {
    pub fn try_from_signed_packet(signed_packet: SignedPacket) -> Result<Self> {
        let announce = NodeAnnounce::from_pkarr_signed_packet(&signed_packet)?;
        Ok(Self {
            announce,
            signed_packet,
        })
    }
}

impl NodeState {
    fn into_record(&self, origin: &Name) -> Result<Record> {
        self.announce.into_hickory_dns_record_with_origin(origin)
    }
}

pub struct NodeAuthority {
    // TODO: persist
    static_authority: InMemoryAuthority,
    announces: parking_lot::RwLock<HashMap<String, NodeState>>,
    origin: LowerName,
    additional_origins: Vec<Name>,
    serial: u32,
}

impl NodeAuthority {
    pub fn new(
        static_authority: InMemoryAuthority,
        origin: Name,
        additional_origins: Vec<Name>,
        serial: u32,
    ) -> Self {
        Self {
            static_authority,
            origin: origin.into(),
            additional_origins,
            serial,
            announces: Default::default(),
        }
    }
    pub fn all_origins(&self) -> impl IntoIterator<Item = Name> {
        let origin = Name::from(self.origin());
        Some(origin)
            .iter()
            .chain(self.additional_origins.iter())
            .cloned()
            .collect::<Vec<_>>()
    }

    pub fn allowed_origin(&self, origin: &Name) -> bool {
        let our_origin: &Name = self.origin.borrow();
        our_origin == origin || self.additional_origins.contains(origin)
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn upsert_pkarr(&self, signed_packet: SignedPacket) -> Result<(NodeId, bool)> {
        let id = iroh_base::base32::fmt(signed_packet.public_key().to_bytes());
        match self.announces.write().entry(id) {
            hash_map::Entry::Vacant(entry) => {
                let state = NodeState::try_from_signed_packet(signed_packet)?;
                let node_id = state.announce.node_id;
                entry.insert(state);
                Ok((node_id, true))
            }
            hash_map::Entry::Occupied(mut entry) => {
                let node_id = entry.get().announce.node_id;
                let existing = &entry.get().signed_packet;
                if signed_packet.more_recent_than(existing) {
                    let state = NodeState::try_from_signed_packet(signed_packet)?;
                    let node_id = state.announce.node_id;
                    entry.insert(state);
                    Ok((node_id, true))
                } else {
                    Ok((node_id, false))
                }
            }
        }
    }

    pub async fn resolve_record_for_node(
        &self,
        node_id: &str,
        origin: &Name,
    ) -> Result<Option<Record>, LookupError> {
        match self.announces.read().get(node_id) {
            Some(state) => {
                // todo: cache?
                let record = state
                    .into_record(&origin)
                    .map_err(|_| LookupError::from(ResponseCode::Refused))?;
                Ok(Some(record))
            }
            None => {
                Ok(None)
            }
        }
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
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        match record_type {
            RecordType::TXT => {
                let name2: Name = name.into();
                let Ok((node_id, origin)) = parse_iroh_node_name(&name2) else {
                    return self
                        .static_authority
                        .lookup(name, record_type, lookup_options)
                        .await;
                };
                if !self.allowed_origin(&origin) {
                    return Err(LookupError::from(ResponseCode::NXDomain));
                }
                match self.resolve_record_for_node(&node_id, &origin).await? {
                    Some(record) => {
                        let record_set = record_set(self.serial(), record);
                        let records = LookupRecords::new(lookup_options, Arc::new(record_set));
                        let answers = AuthLookup::answers(records, None);
                        Ok(answers)
                    }
                    None => Err(LookupError::from(ResponseCode::NXDomain)),
                }
            }
            _ => {
                self.static_authority
                    .lookup(name, record_type, lookup_options)
                    .await
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

fn parse_iroh_node_name(name: &Name) -> Result<(String, Name)> {
    if name.num_labels() < 2 {
        bail!("name must have at least 2 label");
    }
    let mut labels = name.iter();
    let marker = labels.next().expect("just checked");
    if marker != IROH_NODE_TXT_LABEL.as_bytes() {
        bail!("last label must be _iroh_node");
    }
    let node_id = labels.next().expect("just checked");
    let node_id = std::str::from_utf8(node_id)?.to_string();
    let rest = Name::from_labels(labels)?;
    Ok((node_id, rest))
}
