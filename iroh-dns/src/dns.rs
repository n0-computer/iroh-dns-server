// use hickory_proto::serialize::binary::BinDecodable;

// fn simple_dns_to_hickory(
//     signed_packet: &pkarr::SignedPacket,
// ) -> anyhow::Result<hickory_proto::op::Message> {
//     let encoded = signed_packet.encoded_packet();
//     let parsed1 = pkarr::dns::Packet::parse(&encoded)?;
//     println!("simple_dns {parsed1:#?}");
//     let parsed2 = hickory_proto::op::Message::from_bytes(&encoded)?;
//     println!("hickory {parsed2:#?}");
//     Ok(parsed2)
// }

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use url::Url;

    use crate::packet::NodeAnnounce;

    #[test]
    fn convert2() -> anyhow::Result<()> {
        let key = iroh_net::key::SecretKey::generate();
        let node_id = key.public();
        let home_derp: Url = "https://derp.example".parse()?;
        let a = NodeAnnounce {
            node_id,
            home_derp: Some(home_derp),
            home_dns: Default::default(),
        };
        let packet_simpdns = a.into_hickory_answers_message()?;
        let packet_hickory = a.into_hickory_answers_message()?;
        let buf_simpdns = packet_simpdns.to_bytes()?;
        let buf_hickory = packet_hickory.to_bytes()?;
        println!(
            "simple_dns {} {}",
            buf_simpdns.len(),
            hex::encode(&buf_simpdns)
        );
        println!(
            "hickory    {} {}",
            buf_hickory.len(),
            hex::encode(&buf_hickory)
        );
        let _simpdns_from_hickory = pkarr::dns::Packet::parse(&buf_hickory)?;
        let _hickory_form_simpdns = hickory_proto::op::Message::from_bytes(&buf_simpdns)?;

        Ok(())
    }

    #[test]
    fn convert() -> anyhow::Result<()> {
        use hickory_proto as proto;
        use pkarr::dns;
        let ttl = 300;
        let (packet1, bytes1) = {
            use dns::rdata;
            let mut packet = dns::Packet::new_reply(0);
            let name = dns::Name::new("foo")?;
            let rdata = rdata::RData::TXT(rdata::TXT::new().with_string("bar")?);
            let record = dns::ResourceRecord::new(name, dns::CLASS::IN, ttl, rdata);
            packet.answers.push(record);
            let bytes = packet.build_bytes_vec()?;
            (packet, bytes)
        };
        let (packet2, bytes2) = {
            use proto::rr;
            use proto::serialize::binary::BinEncodable;
            let mut packet = proto::op::Message::new();
            let name = rr::Name::from_str("foo")?;
            let rdata = rr::RData::TXT(rr::rdata::TXT::new(vec!["bar".to_string()]));
            let mut record = rr::Record::with(name, rr::RecordType::TXT, ttl);
            record.set_data(Some(rdata));
            packet.answers_mut().push(record);
            let bytes = packet.to_bytes()?;
            (packet, bytes)
        };
        println!("simple_dns deb {:#?}", packet1);
        println!("hickory    deb {:#?}", packet2);
        println!("simple_dns len {}", bytes1.len());
        println!("hickory    len {}", bytes2.len());
        println!("simple_dns hex {}", hex::encode(&bytes1));
        println!("hickory    hex {}", hex::encode(&bytes2));

        Ok(())
    }
}
