use std::path::Path;

use anyhow::Result;
use bytes::Bytes;
use iroh_metrics::inc;
use pkarr::{PublicKey, SignedPacket};
use redb::{backends::InMemoryBackend, Database, ReadableTable, TableDefinition};

use crate::metrics::Metrics;

type PublicKeyBytes = [u8; 32];

const SIGNED_PACKETS_TABLE: TableDefinition<&PublicKeyBytes, &[u8]> =
    TableDefinition::new("signed-packets-1");

pub struct SignedPacketStore {
    db: Database,
}

impl SignedPacketStore {
    pub fn open_file(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::builder().create(path)?;
        Self::open(db)
    }

    pub fn open_inmemory() -> Result<Self> {
        let db = Database::builder().create_with_backend(InMemoryBackend::new())?;
        Self::open(db)
    }

    pub fn open(db: Database) -> Result<Self> {
        let write_tx = db.begin_write()?;
        {
            let _table = write_tx.open_table(SIGNED_PACKETS_TABLE)?;
        }
        write_tx.commit()?;
        Ok(Self { db })
    }

    pub fn upsert(&self, packet: SignedPacket) -> Result<bool> {
        let key = packet.public_key();
        let tx = self.db.begin_write()?;
        let mut inserted = true;
        {
            let mut table = tx.open_table(SIGNED_PACKETS_TABLE)?;
            if let Some(existing) = get_packet(&table, &key)? {
                inserted = false;
                if existing.more_recent_than(&packet) {
                    return Ok(false);
                }
            }
            let value = packet.as_bytes();
            table.insert(&key.to_bytes(), &value[..])?;
        }
        tx.commit()?;
        if inserted {
            inc!(Metrics, store_packets_inserted);
        } else {
            inc!(Metrics, store_packets_updated);
        }
        Ok(true)
    }

    pub fn get(&self, key: &PublicKey) -> Result<Option<SignedPacket>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(SIGNED_PACKETS_TABLE)?;
        get_packet(&table, key)
    }

    pub fn remove(&self, key: &PublicKey) -> Result<bool> {
        let tx = self.db.begin_write()?;
        let updated = {
            let mut table = tx.open_table(SIGNED_PACKETS_TABLE)?;
            let did_remove = table.remove(key.as_bytes())?.is_some();
            did_remove
        };
        tx.commit()?;
        if updated {
            inc!(Metrics, store_packets_removed)
        }
        Ok(updated)
    }

    pub fn iter(&self) -> Result<impl Iterator<Item = Result<SignedPacket>>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(SIGNED_PACKETS_TABLE)?;
        let range = table.range::<&PublicKeyBytes>(..)?;
        let iter = range.map(|row| match row {
            Err(err) => Err(anyhow::Error::from(err)),
            Ok((_k, v)) => {
                let value = Bytes::from(v.value().to_vec());
                let packet = SignedPacket::from_bytes(value, false)?;
                Ok(packet)
            }
        });
        Ok(iter)
    }
}

fn get_packet(
    table: &impl ReadableTable<&'static PublicKeyBytes, &'static [u8]>,
    key: &PublicKey,
) -> Result<Option<SignedPacket>> {
    let Some(row) = table.get(&key.to_bytes())? else {
        return Ok(None);
    };
    let packet = SignedPacket::from_bytes(row.value().to_vec().into(), false)?;
    Ok(Some(packet))
}
