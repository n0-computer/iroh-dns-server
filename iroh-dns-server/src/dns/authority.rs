use anyhow::{bail, Context};
use async_trait::async_trait;
use hickory_proto::{
    error::ProtoError,
    op::ResponseCode,
    rr::{
        dnssec::{
            rdata::{
                key::{KeyTrust, KeyUsage, Protocol},
                DNSSECRData, KEY, SIG,
            },
            tbs, Algorithm, Verifier,
        },
        rdata::CNAME,
        LowerName, Name, RData, Record, RecordType,
    },
};
use hickory_server::{
    authority::{
        AuthLookup, Authority, LookupError, LookupOptions, MessageRequest, UpdateRequest,
        UpdateResult, ZoneType,
    },
    server::RequestInfo,
    store::in_memory::InMemoryAuthority,
};
use iroh_dns::packet::{NodeAnnounce, DEFAULT_TTL, IROH_NODE_TXT_NAME};
use iroh_net::key::{PublicKey, Signature};
use tracing::{debug, info};

pub struct IrohAuthority {
    pub(super) inner: InMemoryAuthority,
    pub(super) additional_origins: Vec<Name>,
}

impl IrohAuthority {
    pub async fn update_records(&self, records: &[Record]) -> bool {
        let serial: u32 = self.inner.serial().await;
        let mut updated = false;
        for rr in records {
            updated |= self.inner.upsert(rr.clone(), serial).await;
            debug!(?rr, ?updated, ?serial, "insert record");
        }
        updated
    }

    pub async fn insert_node_announce(&self, an: NodeAnnounce) -> anyhow::Result<bool> {
        let record = an.into_hickory_dns_record_with_origin(self.origin())?;
        let name = record.name().clone();
        let updated = self.update_records(&[record]).await;
        for origin in &self.additional_origins {
            let zoned_name = format!("{}.{}", IROH_NODE_TXT_NAME, an.node_id);
            let zoned_name = Name::parse(&zoned_name, Some(origin))?;
            let rdata = RData::CNAME(CNAME(name.clone()));
            let record = Record::from_rdata(zoned_name, DEFAULT_TTL, rdata);
            let _ = self.update_records(&[record]).await;
        }
        Ok(updated)
    }
}

#[async_trait]
impl Authority for IrohAuthority {
    type Lookup = AuthLookup;
    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.inner.zone_type()
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        self.inner.is_axfr_allowed()
    }

    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        let public_key = verify_sig0(&update).map_err(|e| {
            debug!("sig0 verification failed: {e}");
            ResponseCode::BADSIG
        })?;
        let origin = self.origin();
        let node_zone = node_zone(public_key, origin).map_err(|e| {
            debug!("node zone name is too long: {e}");
            ResponseCode::FormErr
        })?;
        let records = update.updates();
        verify_all_in_zone(&node_zone, records).map_err(|e| {
            debug!("record zone verification failed: {e}");
            ResponseCode::NotZone
        })?;
        let updated = self.update_records(records).await;
        Ok(updated)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        self.inner.origin()
    }

    async fn lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        info!("LOOKUP {name} {record_type} {lookup_options:?}");
        let res = self.inner.lookup(name, record_type, lookup_options).await;
        info!("LOOKUP res {res:?}");
        res
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        info!(
            "SEARCH {:?} {:?} {lookup_options:?}",
            request_info.header, request_info.query
        );
        info!("SEARCH {:#?}", self.inner.records().await);
        let res = self.inner.search(request_info, lookup_options).await;
        info!("SEARCH res {res:?}");
        res
    }

    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.inner.get_nsec_records(name, lookup_options).await
    }
}

fn node_zone(public_key: PublicKey, origin: impl Into<Name>) -> Result<Name, ProtoError> {
    let name = Name::from_utf8(public_key.to_string())?;
    let zone = name.append_name(&origin.into())?;
    Ok(zone)
}

fn verify_all_in_zone(zone: &Name, updates: &[Record]) -> anyhow::Result<()> {
    for record in updates {
        if !zone.zone_of(&record.name()) {
            bail!("{} is not in zone {zone}", record.name())
        }
    }
    Ok(())
}

fn verify_sig0(message: &MessageRequest) -> anyhow::Result<PublicKey> {
    let sig0s = message.sig0();
    debug!("authorizing with: {:?}", sig0s);
    let mut sigs = sig0s.iter().filter_map(|sig0| {
        sig0.data()
            .and_then(RData::as_dnssec)
            .and_then(DNSSECRData::as_sig)
    });
    let sig = sigs.next().context("no signature found")?;

    let name = sig.signer_name();
    let public_key = parse_name_as_root_pubkey(&name)?;

    let res = verify_message(&message, sig, public_key);
    match res {
        Ok(()) => {
            debug!("signature is valid!");
            Ok(public_key)
        }
        Err(err) => {
            debug!("signature is invalid, abort");
            Err(err.into())
        }
    }
}

fn parse_name_as_root_pubkey(name: &Name) -> anyhow::Result<PublicKey> {
    if !name.is_fqdn() || name.num_labels() != 1 {
        bail!("signer name must be a fully-qualified domain name with a single label")
    }
    let label = name.iter().next().expect("just checked");
    let name = std::str::from_utf8(&label)?;
    let public_key: PublicKey = name.parse()?;
    Ok(public_key)
}

fn verify_message(
    message: &MessageRequest,
    sig: &SIG,
    public_key: PublicKey,
) -> anyhow::Result<()> {
    // This is the verification logic from hickory_server::sqlite::authority
    // let key = KEY::new(
    //     Default::default(),
    //     Default::default(),
    //     Default::default(),
    //     Default::default(),
    //     Algorithm::ED25519,
    //     public_key.as_bytes().to_vec(),
    // );
    // let res = key.verify_message(update_message, sig.sig(), sig);

    // this is the simpler version of the above, skipping the KEY construction
    let signable = tbs::message_tbs(message, &sig)?;
    let signature_bytes = sig.sig();
    let signature = Signature::from_bytes(signature_bytes.try_into()?);
    public_key.verify(signable.as_ref(), &signature)?;
    Ok(())
}

// //! DNS Request Handler
//
// // use crate::{
// //     db::{self, Pool},
// //     models::account::AccountRecord,
// // };
// use anyhow::Result;
// use async_trait::async_trait;
// use hickory_server::{
//     authority::{
//         AuthLookup, Authority, LookupError, LookupOptions, LookupRecords, MessageRequest,
//         UpdateResult, ZoneType,
//     },
//     proto::{
//         op::ResponseCode,
//         rr::{
//             rdata::{SOA, TXT},
//             LowerName, RData, Record, RecordSet, RecordType,
//         },
//     },
//     resolver::{error::ResolveError, Name},
//     server::RequestInfo,
// };
// use std::{borrow::Borrow, sync::Arc};
//
// /// DNS Request Handler for user DIDs of the form `_did.<username>.<server origin>`
// #[derive(Debug)]
// pub struct UserDidsAuthority {
//     db_pool: Pool,
//     origin: LowerName,
//     default_soa: SOA,
//     default_ttl: u32,
// }
//
// impl UserDidsAuthority {
//     /// Create a new database backed authority
//     pub fn new(db_pool: Pool, origin: LowerName, default_soa: SOA, default_ttl: u32) -> Self {
//         UserDidsAuthority {
//             db_pool,
//             origin,
//             default_soa,
//             default_ttl,
//         }
//     }
//
//     async fn db_lookup_user_did(&self, username: String) -> Result<String> {
//         let conn = &mut db::connect(&self.db_pool).await?;
//         let account = AccountRecord::find_by_username(conn, username).await?;
//         Ok(account.did)
//     }
// }
//
// #[async_trait]
// impl Authority for UserDidsAuthority {
//     type Lookup = AuthLookup;
//
//     fn zone_type(&self) -> ZoneType {
//         ZoneType::Primary
//     }
//
//     fn is_axfr_allowed(&self) -> bool {
//         false
//     }
//
//     async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
//         Err(ResponseCode::NotImp)
//     }
//
//     fn origin(&self) -> &LowerName {
//         &self.origin
//     }
//
//     async fn lookup(
//         &self,
//         name: &LowerName,
//         query_type: RecordType,
//         lookup_options: LookupOptions,
//     ) -> Result<Self::Lookup, LookupError> {
//         if !matches!(query_type, RecordType::TXT) {
//             tracing::debug!(
//                 ?query_type,
//                 "Aborting DNS lookup on user DIDs, only TXT supported."
//             );
//             return Ok(AuthLookup::Empty);
//         }
//
//         tracing::debug!(?name, "Starting user DID DNS lookup");
//
//         let name: &Name = name.borrow();
//         let mut name_parts = name.iter();
//
//         match name_parts.next() {
//             // Serve requests for e.g. _did.alice.fission.name
//             Some(b"_did") => {
//                 let Some(user_bytes) = name_parts.next() else {
//                     return Ok(AuthLookup::Empty);
//                 };
//
//                 let base = Name::from_labels(name_parts)
//                     .map_err(|e| LookupError::ResolveError(ResolveError::from(e)))?;
//
//                 // base needs to be fission.name, if the request was _did.alice.fission.name
//                 if base != self.origin().clone().into() {
//                     return Ok(AuthLookup::Empty);
//                 }
//
//                 let username = String::from_utf8(user_bytes.to_vec()).map_err(|e| {
//                     LookupError::ResolveError(
//                         format!("Failed decoding non-utf8 subdomain segment: {e}").into(),
//                     )
//                 })?;
//
//                 tracing::info!(%name, %username, "Looking up DID record");
//
//                 let account_did = match self.db_lookup_user_did(username).await {
//                     Ok(account_did) => account_did,
//                     Err(err) => {
//                         tracing::debug!(?err, "Account lookup failed during _did DNS entry lookup");
//                         return Ok(AuthLookup::Empty);
//                     }
//                 };
//
//                 Ok(AuthLookup::answers(
//                     LookupRecords::new(
//                         lookup_options,
//                         Arc::new(did_record_set(
//                             name,
//                             account_did,
//                             self.default_ttl,
//                             self.default_soa.serial(),
//                         )),
//                     ),
//                     None,
//                 ))
//             }
//             Some(b"_dnslink") => {
//                 tracing::warn!(?name, "DNSLink lookup not yet implemented. Ignoring");
//
//                 Ok(AuthLookup::Empty)
//             }
//             _ => Ok(AuthLookup::Empty),
//         }
//     }
//
//     async fn search(
//         &self,
//         request_info: RequestInfo<'_>,
//         lookup_options: LookupOptions,
//     ) -> Result<Self::Lookup, LookupError> {
//         tracing::debug!(query = ?request_info.query, "DNS search matching for user dids.");
//
//         let lookup_name = request_info.query.name();
//         let record_type: RecordType = request_info.query.query_type();
//
//         match record_type {
//             RecordType::TXT => self.lookup(lookup_name, record_type, lookup_options).await,
//             RecordType::SOA => Ok(AuthLookup::answers(
//                 LookupRecords::new(
//                     lookup_options,
//                     Arc::new(record_set(
//                         &self.origin().into(),
//                         record_type,
//                         self.default_soa.serial(),
//                         Record::from_rdata(
//                             self.origin().into(),
//                             self.default_ttl,
//                             RData::SOA(self.default_soa.clone()),
//                         ),
//                     )),
//                 ),
//                 None,
//             )),
//             _ => {
//                 tracing::debug!(
//                     %record_type,
//                     "Aborting query: only TXT (and SOA) record type(s) supported."
//                 );
//                 Ok(AuthLookup::Empty)
//             }
//         }
//     }
//
//     async fn get_nsec_records(
//         &self,
//         _name: &LowerName,
//         _lookup_options: LookupOptions,
//     ) -> Result<Self::Lookup, LookupError> {
//         Ok(AuthLookup::Empty)
//     }
// }
//
// /// Create a DID DNS entry represented as a RecordSet
// pub(crate) fn did_record_set(name: &Name, did: String, ttl: u32, serial: u32) -> RecordSet {
//     let record = Record::from_rdata(name.clone(), ttl, RData::TXT(TXT::new(vec![did])));
//     record_set(name, RecordType::TXT, serial, record)
// }
//
// /// Create a record set with a single record inside
// pub(crate) fn record_set(
//     name: &Name,
//     record_type: RecordType,
//     serial: u32,
//     record: Record,
// ) -> RecordSet {
//     let mut record_set = RecordSet::new(name, record_type, serial);
//     record_set.insert(record, serial);
//     record_set
// }
