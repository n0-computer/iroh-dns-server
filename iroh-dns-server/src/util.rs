use std::collections::{btree_map, BTreeMap};

use anyhow::Result;
use hickory_proto::{
    op::Message,
    rr::{domain::{IntoLabel, Label}, Name, Record, RecordSet, RecordType, RrKey},
    serialize::binary::BinDecodable,
};
use pkarr::SignedPacket;

pub fn signed_packet_to_hickory_message(signed_packet: &SignedPacket) -> Result<Message> {
    let encoded = signed_packet.encoded_packet();
    let message = Message::from_bytes(&encoded)?;
    Ok(message)
}

pub fn signed_packet_to_hickory_records_without_origin(
    signed_packet: &SignedPacket,
    filter: impl Fn(&Record) -> bool,
    ) -> Result<(Label, BTreeMap<RrKey, RecordSet>)> {
    let common_zone = Label::from_utf8(&signed_packet.public_key().to_z32())?;
    let mut message = signed_packet_to_hickory_message(signed_packet)?;
    let answers = message.take_answers();
    let mut output: BTreeMap<RrKey, RecordSet> = BTreeMap::new();
    for mut record in answers.into_iter() {
        // disallow SOA and NS records
        if matches!(record.record_type(), RecordType::SOA | RecordType::NS) {
            continue;
        }
        // expect the z32 encoded pubkey as root name
        let name = record.name();
        if name.num_labels() < 1 {
            continue;
        }
        let zone = Label::from(name.iter().last().unwrap().into_label()?);
        if zone != common_zone {
            continue;
        }
        if !filter(&record) {
            continue;
        }

        let name_without_zone = Name::from_labels(name.iter().take(name.num_labels() as usize - 1))?;
        record.set_name(name_without_zone);

        let rrkey = RrKey::new(record.name().into(), record.record_type());
        match output.entry(rrkey) {
            btree_map::Entry::Vacant(e) => {
                let set: RecordSet = record.into();
                e.insert(set);
            }
            btree_map::Entry::Occupied(mut e) => {
                let set = e.get_mut();
                let serial = set.serial();
                set.insert(record, serial);
            }
        }
    }
    Ok((common_zone, output))

}

pub fn signed_packet_to_hickory_records(
    signed_packet: &SignedPacket,
    append_origin: Option<&Name>,
    filter: impl Fn(&Record) -> bool,
) -> Result<BTreeMap<RrKey, RecordSet>> {
    let mut message = signed_packet_to_hickory_message(signed_packet)?;
    let answers = message.take_answers();
    let mut output: BTreeMap<RrKey, RecordSet> = BTreeMap::new();
    for mut record in answers.into_iter() {
        // disallow SOA and NS records
        if matches!(record.record_type(), RecordType::SOA | RecordType::NS) {
            continue;
        }
        if !filter(&record) {
            continue;
        }
        // append origin if desired
        if let Some(origin) = append_origin {
            let new_name = record.name().clone().append_name(origin)?;
            record.set_name(new_name);
        }
        let rrkey = RrKey::new(record.name().into(), record.record_type());
        match output.entry(rrkey) {
            btree_map::Entry::Vacant(e) => {
                let set: RecordSet = record.into();
                e.insert(set);
            }
            btree_map::Entry::Occupied(mut e) => {
                let set = e.get_mut();
                let serial = set.serial();
                set.insert(record, serial);
            }
        }
    }
    Ok(output)
}

pub fn record_append_origin(record: &mut Record, origin: &Name) -> Result<()> {
    let new_name = record.name().clone().append_name(origin)?;
    record.set_name(new_name.clone());
    Ok(())
}

pub fn record_set_append_origin(input: &RecordSet, origin: &Name, serial: u32) -> Result<RecordSet> {
    let new_name = input.name().clone().append_name(origin)?;
    let mut output = RecordSet::new(&new_name, input.record_type(), serial);
    // TODO: less clones
    for record in input.records_without_rrsigs() {
        let mut record = record.clone();
        record.set_name(new_name.clone());
        output.insert(record, serial);
    }
    Ok(output)
}

// /// Create a record set with a single record inside
// pub(crate) fn record_set(
//     serial: u32,
//     record: Record,
// ) -> RecordSet {
//     let mut record_set = RecordSet::new(record.name(), record.record_type(), serial);
//     record_set.insert(record, serial);
//     record_set
// }
// pub fn signed_packet_to_hickory_with_origin(
//     signed_packet: &SignedPacket,
//     origin: &Name,
//     serial: u32,
// ) -> Result<RecordSet> {
// }
// pub fn append_signed_packet_to_hickory_records_with_origin(records: &mut
// BTreeMap<RrKey, RecordSet>, origin: Option<&Name>, signed_packet: &SignedPacket
// ) -> Result<()> {
//     let mut message = signed_packet_to_hickory_message(signed_packet)?;
//     let answers = message.take_answers();
//     // use the timestamp in milisecond precision as serial to
//     let serial = (*signed_packet.timestamp() / 1000) as u32;
//     for record in answers.into_iter() {
//         // disallow SOA and NS records
//         if matches!(record.record_type(), RecordType::SOA | RecordType::NS) {
//             continue;
//         }
//         // change origin if desired
//         if let Some(origin) = origin {
//             record_append_origin(&mut record, origin);
//         }
//         let rrkey = RrKey::new(record.name().into(), record.record_type());
//         match records.entry(rrkey) {
//             btree_map::Entry::Vacant(e) => {
//                 let set = RecordSet::new(record.name())
//                 let set: RecordSet = record.into();
//                 e.insert(set);
//             },
//             btree_map::Entry::Occupied(mut e) => {
//                 let set = e.get_mut();
//                 let serial = set.serial();
//                 set.insert(record, serial);
//             }
//         }
//     }
//
//     todo!()
// }
