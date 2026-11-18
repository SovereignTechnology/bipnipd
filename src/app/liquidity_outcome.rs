//! bipnip: liquidity outcomes (kind 8735) this instance signs about what it coordinated and saw
//! end: each edge of a ring with announced channels (opened or missing), and a lease buyer's
//! bond it took (slashed). Readers trust such statements only from instances they chose
//! (bipnip draft "Liquidity outcomes").
//!
//! An outcome is kept in the outbox table `liquidity_outcomes` when it is decided, and published
//! by the scheduler until a relay takes it ([`publish_pending`]). Its time is the time it was
//! decided, so every attempt is the same event. The instance never writes that a lease's channel
//! closed early, and never names who closed one.

use std::str::FromStr;

use mostro_core::node_binding::Network;
use mostro_core::outcome::{Deal, Outcome, OutcomeResult};
use nostr_sdk::prelude::{FinalizeEvent, Timestamp};
use secp256k1::PublicKey;
use sqlx::{Row, SqlitePool};

use crate::app::context::AppContext;
use mostro_core::prelude::*;

/// Most outcomes published in one pass.
const PUBLISH_BATCH: i64 = 50;

/// An outcome to sign, as decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decided {
    /// Lease or ring edge.
    pub deal: Deal,
    /// The lease id or the ring id.
    pub subject: String,
    /// The network the nodes are on.
    pub network: Network,
    /// The seller and the buyer, or the opener and the receiver (66 hex each).
    pub nodes: [String; 2],
    /// How it ended.
    pub result: OutcomeResult,
    /// The funding outpoint, for an opened edge of an announced ring.
    pub outpoint: Option<String>,
}

fn db_err(e: sqlx::Error) -> MostroError {
    MostroInternalErr(ServiceError::DbAccessError(e.to_string()))
}

fn deal_name(deal: Deal) -> &'static str {
    deal.as_str()
}

fn result_of(name: &str) -> Option<OutcomeResult> {
    Some(match name {
        "kept" => OutcomeResult::Kept,
        "closed-early" => OutcomeResult::ClosedEarly,
        "unpaid" => OutcomeResult::Unpaid,
        "slashed" => OutcomeResult::Slashed,
        "opened" => OutcomeResult::Opened,
        "missing" => OutcomeResult::Missing,
        _ => return None,
    })
}

/// Keeps `decided` in the outbox, at `now`. The same subject and nodes are kept once.
pub async fn queue(pool: &SqlitePool, decided: &Decided, now: u64) -> Result<(), MostroError> {
    sqlx::query(
        "INSERT OR IGNORE INTO liquidity_outcomes \
         (deal, subject, network, node_a, node_b, result, outpoint, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(deal_name(decided.deal))
    .bind(&decided.subject)
    .bind(decided.network.as_str())
    .bind(&decided.nodes[0])
    .bind(&decided.nodes[1])
    .bind(decided.result.as_str())
    .bind(&decided.outpoint)
    .bind(i64::try_from(now).unwrap_or(i64::MAX))
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// The outcome a stored row describes, signed by `instance` (hex).
fn outcome_of(row: &sqlx::sqlite::SqliteRow, instance: &str) -> Option<(Outcome, u64)> {
    let deal = match row.try_get::<String, _>("deal").ok()?.as_str() {
        "lease" => Deal::Lease,
        "ring" => Deal::Ring,
        _ => return None,
    };
    let node = |column: &str| -> Option<PublicKey> {
        PublicKey::from_str(&row.try_get::<String, _>(column).ok()?).ok()
    };
    let outcome = Outcome {
        deal,
        subject: row.try_get("subject").ok()?,
        network: Network::from_str(&row.try_get::<String, _>("network").ok()?).ok()?,
        nodes: [node("node_a")?, node("node_b")?],
        result: result_of(&row.try_get::<String, _>("result").ok()?)?,
        closer: None,
        funding_height: None,
        close_height: None,
        outpoint: row.try_get("outpoint").ok()?,
        instance: Some(instance.to_string()),
    };
    let at = u64::try_from(row.try_get::<i64, _>("created_at").ok()?).ok()?;
    Some((outcome, at))
}

/// Publishes the outcomes in the outbox that no relay took yet, signed with this instance's
/// key. A row that cannot be made into a valid outcome is marked done and logged; one no relay
/// took is tried on the next pass.
pub async fn publish_pending(ctx: &AppContext) {
    let pool = ctx.pool();
    let rows = match sqlx::query(
        "SELECT * FROM liquidity_outcomes WHERE published = 0 ORDER BY id LIMIT ?",
    )
    .bind(PUBLISH_BATCH)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("liquidity outcomes: cannot read the outbox: {e}");
            return;
        }
    };
    let instance = ctx.keys().public_key().to_hex();
    for row in rows {
        let Ok(id) = row.try_get::<i64, _>("id") else {
            continue;
        };
        let event = outcome_of(&row, &instance).and_then(|(outcome, at)| {
            outcome
                .to_event_builder("")
                .ok()?
                .custom_created_at(Timestamp::from(at))
                .finalize(ctx.keys())
                .ok()
        });
        let done = match event {
            None => {
                tracing::warn!("liquidity outcomes: row {id} is not a valid outcome; dropped");
                true
            }
            Some(event) => crate::publish::send_event_first_ack(ctx.nostr_client(), &event, |_| {})
                .await
                .is_ok(),
        };
        if done {
            if let Err(e) = sqlx::query("UPDATE liquidity_outcomes SET published = 1 WHERE id = ?")
                .bind(id)
                .execute(pool)
                .await
            {
                tracing::warn!("liquidity outcomes: cannot mark row {id} published: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> SqlitePool {
        crate::app::liquidity_bond::testing::pool().await
    }

    fn node(n: u8) -> String {
        let mut b = [0u8; 32];
        b[31] = n;
        let sk = secp256k1::SecretKey::from_slice(&b).unwrap();
        PublicKey::from_secret_key(&secp256k1::Secp256k1::signing_only(), &sk).to_string()
    }

    #[tokio::test]
    async fn a_decided_outcome_is_kept_once_and_reads_back_as_a_valid_outcome() {
        let pool = pool().await;
        let decided = Decided {
            deal: Deal::Ring,
            subject: "ab".repeat(32),
            network: Network::Regtest,
            nodes: [node(1), node(2)],
            result: OutcomeResult::Opened,
            outpoint: Some(format!("{}:0", "cd".repeat(32))),
        };
        queue(&pool, &decided, 1_000).await.unwrap();
        queue(&pool, &decided, 2_000).await.unwrap();
        let rows = sqlx::query("SELECT * FROM liquidity_outcomes")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "kept once");
        let (outcome, at) = outcome_of(&rows[0], &"ef".repeat(32)).expect("an outcome");
        assert_eq!(at, 1_000);
        assert_eq!(outcome.result, OutcomeResult::Opened);
        assert_eq!(outcome.nodes[0].to_string(), node(1));
        assert!(outcome.validate().is_ok());
        assert_eq!(result_of("missing"), Some(OutcomeResult::Missing));
        assert_eq!(result_of("great"), None);
    }
}
