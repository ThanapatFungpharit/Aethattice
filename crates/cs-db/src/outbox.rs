//! Per-domain transactional outbox (contract §5.2; spec App. E, C2, §18.4).
//!
//! [`Outbox::append`] is the only write path. It takes the domain transaction, so the event
//! commits atomically with the state change. Sequences are allocated from `outbox_counters`
//! with `UPDATE … RETURNING` (row lock held until commit), which makes them contiguous per
//! partition and makes commit order equal sequence order within a partition. A missing
//! sequence is therefore a real gap, and [`Outbox::read`] reports it.

use crate::error::DbError;
use crate::pool::{DomainPool, DomainTx};
use cs_common::id::{EventId, TenantId};
use cs_common::vector::DomainId;
use serde::Serialize;
use uuid::Uuid;

/// Maximum payload size (row limit, App. E).
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// An event to append.
#[derive(Debug)]
pub struct NewEvent<'a, T: Serialize + ?Sized> {
    pub tenant_id: TenantId,
    /// e.g. `resource.created`: `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`.
    pub event_type: &'a str,
    pub event_version: i32,
    /// Default: the subject resource ID (§11.2).
    pub partition_key: Uuid,
    /// Encoded as deterministic CBOR.
    pub payload: &'a T,
}

/// Where an appended event landed. With the domain's cluster ID this is the consumer dedup
/// key `(cluster_id, domain_id, partition, sequence)` (§18.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxPosition {
    pub domain: DomainId,
    pub partition: i32,
    pub sequence: i64,
    pub event_id: EventId,
}

/// A stored outbox row.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct OutboxRecord {
    pub tenant_id: Uuid,
    pub partition: i32,
    pub sequence: i64,
    pub event_id: Uuid,
    pub event_type: String,
    pub event_version: i32,
    pub partition_key: Uuid,
    pub payload: Vec<u8>,
}

fn valid_event_type(s: &str) -> bool {
    let mut n = 0;
    s.len() <= 128
        && s.split('.').all(|seg| {
            n += 1;
            let b = seg.as_bytes();
            !b.is_empty()
                && b[0].is_ascii_lowercase()
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
        })
        && n >= 2
}

/// Outbox operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct Outbox;

impl Outbox {
    /// `hash(partition_key) mod P`: first 8 bytes of BLAKE3 over the 16 key bytes, big-endian.
    /// Deterministic across nodes and versions.
    pub fn partition_for(key: &Uuid, partitions: u32) -> i32 {
        let h = blake3::hash(key.as_bytes());
        let mut b = [0u8; 8];
        b.copy_from_slice(&h.as_bytes()[..8]);
        let p = u64::from_be_bytes(b) % u64::from(partitions.max(1));
        i32::try_from(p).unwrap_or(0)
    }

    /// Append an event inside `tx`.
    pub async fn append<T: Serialize + ?Sized>(
        tx: &mut DomainTx,
        ev: NewEvent<'_, T>,
    ) -> Result<OutboxPosition, DbError> {
        if !valid_event_type(ev.event_type) {
            return Err(DbError::Invalid(format!(
                "invalid event type {:?}",
                ev.event_type
            )));
        }
        if ev.event_version < 1 {
            return Err(DbError::Invalid("event_version must be >= 1".into()));
        }
        let payload = cs_crypto::cbor::to_canonical(ev.payload)
            .map_err(|e| DbError::Invalid(format!("payload encoding: {e}")))?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(DbError::Invalid(format!(
                "outbox payload {} bytes exceeds {MAX_PAYLOAD_BYTES}",
                payload.len()
            )));
        }
        let partitions = tx.outbox_partitions().await?;
        let partition = Self::partition_for(&ev.partition_key, partitions);
        let event_id = EventId::generate()?;
        let sequence: Option<i64> = sqlx::query_scalar(
            "UPDATE outbox_counters SET next_sequence = next_sequence + 1 \
             WHERE partition = $1 RETURNING next_sequence - 1",
        )
        .bind(partition)
        .fetch_optional(tx.conn())
        .await?;
        let sequence = sequence.ok_or_else(|| {
            DbError::Invalid(format!("outbox partition {partition} has no counter"))
        })?;
        sqlx::query(
            "INSERT INTO outbox (tenant_id, partition, sequence, event_id, event_type, event_version, partition_key, payload) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(ev.tenant_id.as_uuid())
        .bind(partition)
        .bind(sequence)
        .bind(event_id.as_uuid())
        .bind(ev.event_type)
        .bind(ev.event_version)
        .bind(ev.partition_key)
        .bind(&payload)
        .execute(tx.conn())
        .await?;
        Ok(OutboxPosition {
            domain: tx.domain().clone(),
            partition,
            sequence,
            event_id,
        })
    }

    /// Read up to `limit` events of `partition` with `sequence > after`, in order. Fails with
    /// [`DbError::OutboxGap`] if any sequence between `after` and the committed head is
    /// missing.
    pub async fn read(
        pool: &DomainPool,
        partition: i32,
        after: i64,
        limit: i64,
    ) -> Result<Vec<OutboxRecord>, DbError> {
        if limit < 1 || after < 0 {
            return Err(DbError::Invalid("limit must be >= 1 and after >= 0".into()));
        }
        // Read the head first: every sequence below it has committed (commit order equals
        // sequence order), so the rows read afterwards must contain all of them.
        let next: Option<i64> =
            sqlx::query_scalar("SELECT next_sequence FROM outbox_counters WHERE partition = $1")
                .bind(partition)
                .fetch_optional(pool.raw())
                .await?;
        let next =
            next.ok_or_else(|| DbError::Invalid(format!("unknown outbox partition {partition}")))?;
        let rows: Vec<OutboxRecord> = sqlx::query_as(
            "SELECT tenant_id, partition, sequence, event_id, event_type, event_version, partition_key, payload \
             FROM outbox WHERE partition = $1 AND sequence > $2 ORDER BY sequence ASC LIMIT $3",
        )
        .bind(partition)
        .bind(after)
        .bind(limit)
        .fetch_all(pool.raw())
        .await?;
        let mut expected = after + 1;
        for r in &rows {
            if r.sequence != expected {
                return Err(DbError::OutboxGap {
                    partition,
                    expected,
                    found: Some(r.sequence),
                });
            }
            expected += 1;
        }
        // Fewer rows than requested but the head is further on: the tail is missing.
        let head_last = next - 1;
        if (rows.len() as i64) < limit && expected <= head_last {
            return Err(DbError::OutboxGap {
                partition,
                expected,
                found: None,
            });
        }
        Ok(rows)
    }

    /// Number of partitions of this domain's outbox.
    pub async fn partition_count(pool: &DomainPool) -> Result<u32, DbError> {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox_counters")
            .fetch_one(pool.raw())
            .await?;
        u32::try_from(n).map_err(|_| DbError::Invalid("bad partition count".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partitioning_is_stable() {
        let k = Uuid::from_bytes([1; 16]);
        let p = Outbox::partition_for(&k, 16);
        assert!((0..16).contains(&p));
        assert_eq!(p, Outbox::partition_for(&k, 16));
        // golden value: guards against accidental changes of the hash mapping
        assert_eq!(Outbox::partition_for(&Uuid::nil(), 16), {
            let h = blake3::hash(&[0u8; 16]);
            (u64::from_be_bytes(h.as_bytes()[..8].try_into().unwrap()) % 16) as i32
        });
    }

    #[test]
    fn event_types() {
        assert!(valid_event_type("resource.created"));
        assert!(valid_event_type("a.b_c.d1"));
        for bad in [
            "resource",
            "Resource.created",
            "resource.",
            ".x",
            "a..b",
            "a.b-c",
        ] {
            assert!(!valid_event_type(bad), "{bad}");
        }
    }
}
