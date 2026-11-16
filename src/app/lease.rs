//! bipnip: liquidity lease coordination (bipnip repo, `docs/nips/liquidity-leases.md`).
//!
//! The instance checks lease messages and relays them between a seller and a buyer. It never
//! holds the lease payment: the buyer pays a hold invoice on the seller's own node, on a hash
//! whose preimage only the buyer knows, and hands the preimage to the seller peer to peer.
//! `lease-preimage` is therefore refused here, and nothing in this module or its tables can
//! store a preimage.
//!
//! One offer leads to at most one lease. Its state lives in `lease_offers.status`:
//!
//! ```text
//! pending -> taken -> invoiced -> opened -> active -> completion
//!    \________\__________\__________\-> canceled
//! pending -> expired
//! ```
//!
//! Every step is a compare-and-swap on that column, so a repeated or out-of-order message
//! changes nothing and relays nothing. Seller steps must come from the identity that made the
//! offer; identities are the ones the transport proved, and each must be bound to the node the
//! message names.
//!
//! Each offer has a public order event (kind 38735) that follows its state as `pending`,
//! `in-progress`, `success` or `canceled`. Publishing is best effort when a step is handled, and
//! the housekeeping job retries whatever is behind. The same job expires offers nobody took and
//! cancels leases that stalled during setup.

use crate::app::context::AppContext;
use crate::util::enqueue_order_msg;
use mostro_core::lease_message::{LeaseOffer, LeasePayload};
use mostro_core::lease_order::{LeaseOrder, LeaseOrderStatus};
use mostro_core::prelude::*;
use nostr_sdk::prelude::{Event, FinalizeEvent, Keys, PublicKey, Timestamp};
use sqlx::{Row, SqliteConnection, SqlitePool};
use std::future::Future;
use uuid::Uuid;

/// Most offers one identity may have open at a time.
const MAX_OPEN_OFFERS_PER_SELLER: i64 = 20;
/// Longest an offer may stay open: 30 days.
const MAX_OFFER_LIFETIME_SECS: u64 = 30 * 24 * 3600;
/// Oldest contract a take may carry: one hour. A contract is written for the take it is sent in.
const MAX_CONTRACT_AGE_SECS: u64 = 3600;
/// How far ahead of this instance's clock a contract may be dated.
const MAX_CONTRACT_FUTURE_SECS: u64 = 600;
/// Longest a lease may sit between two setup steps: 48 hours, the longest a hold invoice lives.
/// A lease with no step for that long is canceled by the housekeeping job.
const LEASE_SETUP_TIMEOUT_SECS: u64 = 48 * 3600;
/// Most order events one housekeeping pass brings up to date.
const MAX_ORDER_EVENTS_PER_PASS: i64 = 100;

const PENDING: &str = "pending";
const TAKEN: &str = "taken";
const INVOICED: &str = "invoiced";
const OPENED: &str = "opened";
const ACTIVE: &str = "active";
const COMPLETION: &str = "completion";
const CANCELED: &str = "canceled";
/// Nobody took the offer before its expiry. Set by the housekeeping job only.
const EXPIRED: &str = "expired";

/// One order event is built and sent at a time, so the status a relay holds last is the one
/// read last.
static ORDER_EVENTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn now() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

fn db_err(e: sqlx::Error) -> MostroError {
    MostroInternalErr(ServiceError::DbAccessError(e.to_string()))
}

fn refuse(reason: CantDoReason) -> MostroError {
    MostroCantDo(reason)
}

fn stored_key(hex: &str) -> Result<PublicKey, MostroError> {
    PublicKey::parse(hex).map_err(|_| MostroInternalErr(ServiceError::InvalidPubkey))
}

/// An offer row.
struct Offer {
    seller_identity: String,
    seller_trade_pubkey: String,
    offer: LeaseOffer,
    status: String,
}

/// The take of an offer.
struct Lease {
    lease_id: String,
    buyer_identity: String,
    buyer_trade_pubkey: String,
}

async fn offer_by_id(pool: &SqlitePool, id: Uuid) -> Result<Option<Offer>, MostroError> {
    let row = sqlx::query(
        "SELECT seller_identity, seller_trade_pubkey, offer, status FROM lease_offers WHERE id = ?",
    )
    .bind(id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let json: String = row.try_get("offer").map_err(db_err)?;
    let offer = serde_json::from_str(&json)
        .map_err(|_| MostroInternalErr(ServiceError::MessageSerializationError))?;
    Ok(Some(Offer {
        seller_identity: row.try_get("seller_identity").map_err(db_err)?,
        seller_trade_pubkey: row.try_get("seller_trade_pubkey").map_err(db_err)?,
        offer,
        status: row.try_get("status").map_err(db_err)?,
    }))
}

async fn lease_by_offer(pool: &SqlitePool, id: Uuid) -> Result<Option<Lease>, MostroError> {
    let row = sqlx::query(
        "SELECT lease_id, buyer_identity, buyer_trade_pubkey FROM leases WHERE offer_id = ?",
    )
    .bind(id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(Lease {
        lease_id: row.try_get("lease_id").map_err(db_err)?,
        buyer_identity: row.try_get("buyer_identity").map_err(db_err)?,
        buyer_trade_pubkey: row.try_get("buyer_trade_pubkey").map_err(db_err)?,
    }))
}

/// Moves an offer from one of `from` to `to`; false when it was in none of them (someone else
/// moved it first, or the message is out of order). Takes a connection so a caller can make the
/// move part of a transaction.
async fn advance(
    conn: &mut SqliteConnection,
    id: Uuid,
    from: &[&str],
    to: &str,
) -> Result<bool, MostroError> {
    // `from` only ever holds this module's own constants.
    for state in from {
        let done = sqlx::query("UPDATE lease_offers SET status = ? WHERE id = ? AND status = ?")
            .bind(to)
            .bind(id.to_string())
            .bind(*state)
            .execute(&mut *conn)
            .await
            .map_err(db_err)?;
        if done.rows_affected() == 1 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn lease_payload(msg: &Message) -> Result<&LeasePayload, MostroError> {
    match msg.get_inner_message_kind().get_payload() {
        Some(Payload::Lease(payload)) => Ok(payload),
        _ => Err(refuse(CantDoReason::InvalidPayload)),
    }
}

fn order_id(msg: &Message) -> Result<Uuid, MostroError> {
    msg.get_inner_message_kind()
        .id
        .ok_or(refuse(CantDoReason::InvalidParameters))
}

/// True when the message's id is a lease offer's. Used to keep a `cancel` for a lease away from
/// the escrow cancel path. A database error counts as "not a lease": the escrow path then
/// answers as it would for any unknown order.
pub async fn names_a_lease(ctx: &AppContext, msg: &Message) -> bool {
    let Some(id) = msg.get_inner_message_kind().id else {
        return false;
    };
    matches!(offer_by_id(ctx.pool(), id).await, Ok(Some(_)))
}

/// Routes one lease action.
pub async fn lease_action(
    ctx: &AppContext,
    action: &Action,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    match action {
        Action::LeaseOffer => lease_offer_action(ctx, msg, event).await,
        Action::TakeLease => take_lease_action(ctx, msg, event).await,
        Action::LeaseInvoice => seller_step(ctx, msg, event, &[TAKEN], INVOICED).await,
        Action::LeaseChannelOpened => seller_step(ctx, msg, event, &[INVOICED], OPENED).await,
        Action::LeaseActive => seller_step(ctx, msg, event, &[OPENED], ACTIVE).await,
        Action::LeaseCompletionInvoice => seller_step(ctx, msg, event, &[ACTIVE], COMPLETION).await,
        // The preimage goes from the buyer to the seller only. An instance that accepted it
        // could settle-and-not-relay or leak it; refusing it here keeps a misdirected client
        // from finding out the hard way. The payload is dropped unread.
        _ => Err(refuse(CantDoReason::InvalidAction)),
    }
}

/// A seller publishes an offer. Checked: the terms over the whole capacity range, the lifetime,
/// and that the seller's node binds the identity key the transport proved. The offer is stored
/// and echoed back with its order id.
async fn lease_offer_action(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    if ctx.maintenance().is_enabled() {
        return Err(refuse(CantDoReason::MaintenanceMode));
    }
    let kind = msg.get_inner_message_kind();
    let LeasePayload::Offer(offer) = lease_payload(&msg)? else {
        return Err(refuse(CantDoReason::InvalidPayload));
    };
    if kind.id.is_some() {
        return Err(refuse(CantDoReason::InvalidParameters));
    }
    offer
        .validate()
        .map_err(|_| refuse(CantDoReason::InvalidParameters))?;
    let now = now();
    if offer.is_expired(now) || offer.expires_at > now.saturating_add(MAX_OFFER_LIFETIME_SECS) {
        return Err(refuse(CantDoReason::InvalidParameters));
    }
    let seller = event.identity.to_hex();
    offer
        .check_binding(&seller, now)
        .map_err(|_| refuse(CantDoReason::NotAuthorized))?;

    let open: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM lease_offers \
         WHERE seller_identity = ? AND status = ? AND expires_at > ?",
    )
    .bind(&seller)
    .bind(PENDING)
    .bind(now as i64)
    .fetch_one(pool)
    .await
    .map_err(db_err)?
    .try_get("n")
    .map_err(db_err)?;
    if open >= MAX_OPEN_OFFERS_PER_SELLER {
        return Err(refuse(CantDoReason::TooManyRequests));
    }

    let id = Uuid::new_v4();
    let json = serde_json::to_string(offer)
        .map_err(|_| MostroInternalErr(ServiceError::MessageSerializationError))?;
    sqlx::query(
        "INSERT INTO lease_offers \
         (id, seller_identity, seller_trade_pubkey, seller_node, network, offer, status, \
          created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(&seller)
    .bind(event.sender.to_hex())
    .bind(&offer.seller_node)
    .bind(offer.network.as_str())
    .bind(json)
    .bind(PENDING)
    .bind(now as i64)
    .bind(offer.expires_at as i64)
    .execute(pool)
    .await
    .map_err(db_err)?;

    enqueue_order_msg(
        kind.request_id,
        Some(id),
        Action::LeaseOffer,
        Some(Payload::Lease(LeasePayload::Offer(offer.clone()))),
        event.sender,
        None,
    )
    .await;
    sync_order_event(ctx, id).await;
    Ok(())
}

/// A buyer takes an offer. Checked: the offer is open; the contract is the offer at an allowed
/// capacity (so the buyer cannot write its own price) and freshly dated; the buyer's node binds
/// the identity the transport proved; the buyer is not the seller. The take goes to the seller,
/// and each side learns the other's trade key (the buyer needs the seller's to release the
/// preimage peer to peer).
async fn take_lease_action(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    if ctx.maintenance().is_enabled() {
        return Err(refuse(CantDoReason::MaintenanceMode));
    }
    let id = order_id(&msg)?;
    let payload = lease_payload(&msg)?;
    let LeasePayload::Take(take) = payload else {
        return Err(refuse(CantDoReason::InvalidPayload));
    };
    let contract = take
        .validate()
        .map_err(|_| refuse(CantDoReason::InvalidParameters))?;
    let row = offer_by_id(pool, id)
        .await?
        .ok_or(refuse(CantDoReason::NotFound))?;
    let now = now();
    if row.status != PENDING || row.offer.is_expired(now) {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    let buyer = event.identity.to_hex();
    if buyer == row.seller_identity {
        return Err(refuse(CantDoReason::InvalidPubkey));
    }
    row.offer
        .check_contract(&contract)
        .map_err(|_| refuse(CantDoReason::InvalidParameters))?;
    if contract.created_at > now.saturating_add(MAX_CONTRACT_FUTURE_SECS)
        || contract.created_at.saturating_add(MAX_CONTRACT_AGE_SECS) < now
    {
        return Err(refuse(CantDoReason::InvalidParameters));
    }
    take.check_binding(&contract, &buyer, now)
        .map_err(|_| refuse(CantDoReason::NotAuthorized))?;
    let seller_trade_key = stored_key(&row.seller_trade_pubkey)?;

    // The state change and the lease row land together or not at all.
    let mut tx = pool.begin().await.map_err(db_err)?;
    let moved = sqlx::query("UPDATE lease_offers SET status = ? WHERE id = ? AND status = ?")
        .bind(TAKEN)
        .bind(id.to_string())
        .bind(PENDING)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    if moved.rows_affected() != 1 {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    let inserted = sqlx::query(
        "INSERT INTO leases \
         (lease_id, offer_id, buyer_identity, buyer_trade_pubkey, buyer_node, contract, \
          created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(contract.id())
    .bind(id.to_string())
    .bind(&buyer)
    .bind(event.sender.to_hex())
    .bind(contract.buyer_node.to_string())
    .bind(&take.contract)
    .bind(now as i64)
    .bind(now as i64)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        // The same contract was already taken elsewhere: dropping the transaction leaves the
        // offer open for another buyer.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(refuse(CantDoReason::InvalidParameters));
        }
        Err(e) => return Err(db_err(e)),
    }
    tx.commit().await.map_err(db_err)?;

    enqueue_order_msg(
        None,
        Some(id),
        Action::TakeLease,
        Some(Payload::Lease(payload.clone())),
        seller_trade_key,
        None,
    )
    .await;
    enqueue_order_msg(
        None,
        Some(id),
        Action::TradePubkey,
        Some(Payload::Peer(Peer::new(event.sender.to_hex(), None))),
        seller_trade_key,
        None,
    )
    .await;
    enqueue_order_msg(
        msg.get_inner_message_kind().request_id,
        Some(id),
        Action::TradePubkey,
        Some(Payload::Peer(Peer::new(row.seller_trade_pubkey, None))),
        event.sender,
        None,
    )
    .await;
    sync_order_event(ctx, id).await;
    Ok(())
}

/// One of the seller's steps after the take: the upfront invoice, the channel report, the
/// lease-active notice, the completion invoice. Checked: the sender is the offer's seller, the
/// payload names this offer's lease, and the offer is in the state the step follows. The message
/// is then relayed to the buyer unchanged. The instance does not vouch for an invoice or a
/// channel it relays: the buyer's own agent and node check both.
async fn seller_step(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
    from: &[&str],
    to: &str,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    let id = order_id(&msg)?;
    let kind = msg.get_inner_message_kind();
    let row = offer_by_id(pool, id)
        .await?
        .ok_or(refuse(CantDoReason::NotFound))?;
    if event.identity.to_hex() != row.seller_identity {
        return Err(refuse(CantDoReason::IsNotYourOrder));
    }
    let lease = lease_by_offer(pool, id)
        .await?
        .ok_or(refuse(CantDoReason::NotAllowedByStatus))?;

    let mut channel = None;
    let named = match kind.get_payload() {
        Some(Payload::Lease(LeasePayload::Invoice(invoice))) => {
            invoice
                .validate()
                .map_err(|_| refuse(CantDoReason::InvalidInvoice))?;
            Some(&invoice.lease_id)
        }
        Some(Payload::Lease(LeasePayload::Channel(report))) => {
            report
                .validate()
                .map_err(|_| refuse(CantDoReason::InvalidParameters))?;
            channel = Some(report);
            Some(&report.lease_id)
        }
        None => None,
        Some(_) => return Err(refuse(CantDoReason::InvalidPayload)),
    };
    if named.is_some_and(|lease_id| *lease_id != lease.lease_id) {
        return Err(refuse(CantDoReason::InvalidParameters));
    }

    let buyer_trade_key = stored_key(&lease.buyer_trade_pubkey)?;

    // The state change and what it records land together or not at all: a lease is never left
    // advanced with nothing relayed because the second write failed.
    let mut tx = pool.begin().await.map_err(db_err)?;
    if !advance(&mut tx, id, from, to).await? {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    let now = now() as i64;
    let recorded = match channel {
        Some(report) => {
            sqlx::query(
                "UPDATE leases SET funding_txid = ?, output_index = ?, updated_at = ? \
                 WHERE offer_id = ?",
            )
            .bind(&report.funding_txid)
            .bind(i64::from(report.output_index))
            .bind(now)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
        }
        None => {
            sqlx::query("UPDATE leases SET updated_at = ? WHERE offer_id = ?")
                .bind(now)
                .bind(id.to_string())
                .execute(&mut *tx)
                .await
        }
    };
    recorded.map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    enqueue_order_msg(
        None,
        Some(id),
        kind.action.clone(),
        kind.payload.clone(),
        buyer_trade_key,
        None,
    )
    .await;
    sync_order_event(ctx, id).await;
    Ok(())
}

/// Cancels a lease offer or a lease that is not active yet. The seller may cancel at any point
/// before `active`; the buyer once it has taken the offer. Bookkeeping only: the buyer's payment
/// is locked at the seller's node, which the seller's agent cancels itself (or the payment times
/// out), so nothing here can keep or move money. The other party is told.
pub async fn lease_cancel_action(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    let id = order_id(&msg)?;
    let row = offer_by_id(pool, id)
        .await?
        .ok_or(refuse(CantDoReason::NotFound))?;
    let lease = lease_by_offer(pool, id).await?;
    let sender = event.identity.to_hex();
    let is_seller = sender == row.seller_identity;
    let is_buyer = lease.as_ref().is_some_and(|l| l.buyer_identity == sender);
    if !is_seller && !is_buyer {
        return Err(refuse(CantDoReason::IsNotYourOrder));
    }
    if row.status == CANCELED {
        return Err(refuse(CantDoReason::OrderAlreadyCanceled));
    }
    // Both keys are read before the state changes, so a bad stored key cannot leave a lease
    // canceled with nobody told.
    let other = match (&lease, is_seller) {
        (Some(lease), true) => Some(stored_key(&lease.buyer_trade_pubkey)?),
        (Some(_), false) => Some(stored_key(&row.seller_trade_pubkey)?),
        (None, _) => None,
    };
    let moved = {
        let mut conn = pool.acquire().await.map_err(db_err)?;
        advance(&mut conn, id, &[PENDING, TAKEN, INVOICED, OPENED], CANCELED).await?
    };
    if !moved {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }

    enqueue_order_msg(
        msg.get_inner_message_kind().request_id,
        Some(id),
        Action::Canceled,
        None,
        event.sender,
        None,
    )
    .await;
    if let Some(other) = other {
        enqueue_order_msg(None, Some(id), Action::Canceled, None, other, None).await;
    }
    sync_order_event(ctx, id).await;
    Ok(())
}

/// The status the public order event shows for an internal one.
fn public_status(status: &str) -> Option<LeaseOrderStatus> {
    Some(match status {
        PENDING => LeaseOrderStatus::Pending,
        TAKEN | INVOICED | OPENED => LeaseOrderStatus::InProgress,
        ACTIVE | COMPLETION => LeaseOrderStatus::Success,
        CANCELED => LeaseOrderStatus::Canceled,
        EXPIRED => LeaseOrderStatus::Expired,
        _ => return None,
    })
}

/// The order event for `offer` under `id`, signed by the instance and dated `at`.
fn order_event(
    keys: &Keys,
    id: Uuid,
    status: LeaseOrderStatus,
    offer: &LeaseOffer,
    at: u64,
) -> Result<Event, MostroError> {
    LeaseOrder::from_offer(id, status, offer)
        .map_err(|_| MostroInternalErr(ServiceError::MessageSerializationError))?
        .to_event_builder()
        .custom_created_at(Timestamp::from(at))
        .finalize(keys)
        .map_err(|e| MostroInternalErr(ServiceError::NostrError(e.to_string())))
}

/// What one attempt to bring an offer's order event up to date did.
#[derive(Debug, PartialEq, Eq)]
enum OrderSync {
    /// The event was already up to date.
    Current,
    /// A new event went out.
    Published,
    /// Nothing needed publishing; the row is marked up to date.
    Skipped,
}

/// Brings the public order event of offer `id` up to date with its status, sending through
/// `send`. Nothing is sent when:
///
/// - the status changed but the public one did not (`taken` to `invoiced`, say);
/// - the offer's expiry has passed: the event carries that expiry (NIP-40), so relays have
///   dropped it and would refuse a new one;
/// - relays never saw the order and it is already over (canceled before its first publish).
///
/// A failed `send` leaves the row behind, and the housekeeping job tries again.
async fn sync_order_event_with<F, Fut>(
    pool: &SqlitePool,
    keys: &Keys,
    id: Uuid,
    now: u64,
    send: F,
) -> Result<OrderSync, MostroError>
where
    F: FnOnce(Event) -> Fut,
    Fut: Future<Output = Result<(), MostroError>>,
{
    let _one_at_a_time = ORDER_EVENTS.lock().await;
    let row = sqlx::query(
        "SELECT offer, status, synced_status, order_event_at FROM lease_offers WHERE id = ?",
    )
    .bind(id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let Some(row) = row else {
        return Ok(OrderSync::Current);
    };
    let status: String = row.try_get("status").map_err(db_err)?;
    let synced: Option<String> = row.try_get("synced_status").map_err(db_err)?;
    if synced.as_deref() == Some(status.as_str()) {
        return Ok(OrderSync::Current);
    }
    let public = public_status(&status).ok_or_else(|| {
        MostroInternalErr(ServiceError::UnexpectedError(format!(
            "lease offer {id} has unknown status {status}"
        )))
    })?;
    let json: String = row.try_get("offer").map_err(db_err)?;
    let offer: LeaseOffer = serde_json::from_str(&json)
        .map_err(|_| MostroInternalErr(ServiceError::MessageSerializationError))?;
    let last_at: Option<i64> = row.try_get("order_event_at").map_err(db_err)?;

    // What relays show now, if anything.
    let shown = synced.as_deref().and_then(public_status);
    let over = matches!(
        public,
        LeaseOrderStatus::Canceled | LeaseOrderStatus::Expired
    );
    let nothing_to_send =
        shown == Some(public) || offer.is_expired(now) || (shown.is_none() && over);
    let (outcome, event_at) = if nothing_to_send {
        (OrderSync::Skipped, last_at)
    } else {
        // Always newer than the last one, so a relay replaces it even within the same second.
        let newer_than_last =
            last_at.map_or(0, |t| u64::try_from(t).unwrap_or(0).saturating_add(1));
        let at = now.max(newer_than_last);
        send(order_event(keys, id, public, &offer, at)?).await?;
        (OrderSync::Published, Some(at as i64))
    };
    sqlx::query("UPDATE lease_offers SET synced_status = ?, order_event_at = ? WHERE id = ?")
        .bind(&status)
        .bind(event_at)
        .bind(id.to_string())
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(outcome)
}

/// Brings the order event of offer `id` up to date on this instance's relays. Best effort: a
/// failure is logged and left to the housekeeping job, and never fails the step that led here.
async fn sync_order_event(ctx: &AppContext, id: Uuid) {
    let client = ctx.nostr_client();
    let synced = sync_order_event_with(ctx.pool(), ctx.keys(), id, now(), |event| async move {
        crate::publish::send_event_first_ack(client, &event, |_| {}).await
    })
    .await;
    if let Err(e) = synced {
        tracing::warn!("lease order {id}: order event not published ({e}); housekeeping retries");
    }
}

/// One housekeeping pass at `now`:
///
/// 1. offers nobody took before their expiry become `expired`;
/// 2. leases with no setup step for [`LEASE_SETUP_TIMEOUT_SECS`] are canceled and both parties
///    told. By then the hold invoice has timed out and the buyer has its money back, so this is
///    bookkeeping; a lease whose seller settled but never reported it active also lands here, and
///    is no less live between the two nodes for it;
/// 3. order events that are behind are brought up to date, stopping at the first failure so dead
///    relays are not hammered.
async fn housekeeping_pass_with<F, Fut>(
    pool: &SqlitePool,
    keys: &Keys,
    now: u64,
    mut send: F,
) -> Result<(), MostroError>
where
    F: FnMut(Event) -> Fut,
    Fut: Future<Output = Result<(), MostroError>>,
{
    sqlx::query("UPDATE lease_offers SET status = ? WHERE status = ? AND expires_at <= ?")
        .bind(EXPIRED)
        .bind(PENDING)
        .bind(now as i64)
        .execute(pool)
        .await
        .map_err(db_err)?;

    let cutoff = now.saturating_sub(LEASE_SETUP_TIMEOUT_SECS) as i64;
    let rows = sqlx::query(
        "SELECT o.id AS id, o.seller_trade_pubkey AS seller, l.buyer_trade_pubkey AS buyer \
         FROM lease_offers o JOIN leases l ON l.offer_id = o.id \
         WHERE o.status IN (?, ?, ?) AND l.updated_at <= ?",
    )
    .bind(TAKEN)
    .bind(INVOICED)
    .bind(OPENED)
    .bind(cutoff)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let mut stalled = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id").map_err(db_err)?;
        let seller: String = row.try_get("seller").map_err(db_err)?;
        let buyer: String = row.try_get("buyer").map_err(db_err)?;
        stalled.push((id, seller, buyer));
    }
    for (id, seller, buyer) in stalled {
        let (Ok(id), Ok(seller), Ok(buyer)) = (
            Uuid::parse_str(&id),
            PublicKey::parse(&seller),
            PublicKey::parse(&buyer),
        ) else {
            tracing::warn!("lease housekeeping: skipping a stalled lease with a malformed row");
            continue;
        };
        let moved = {
            let mut conn = pool.acquire().await.map_err(db_err)?;
            advance(&mut conn, id, &[TAKEN, INVOICED, OPENED], CANCELED).await?
        };
        if moved {
            for party in [seller, buyer] {
                enqueue_order_msg(None, Some(id), Action::Canceled, None, party, None).await;
            }
        }
    }

    let rows = sqlx::query(
        "SELECT id FROM lease_offers WHERE synced_status IS NULL OR synced_status != status \
         ORDER BY created_at LIMIT ?",
    )
    .bind(MAX_ORDER_EVENTS_PER_PASS)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let mut behind = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id").map_err(db_err)?;
        behind.push(id);
    }
    for id in behind {
        let Ok(id) = Uuid::parse_str(&id) else {
            continue;
        };
        sync_order_event_with(pool, keys, id, now, &mut send).await?;
    }
    Ok(())
}

/// One housekeeping pass now, on this instance's relays. Called by the scheduler.
pub async fn housekeeping_pass(ctx: &AppContext) {
    let client = ctx.nostr_client();
    let pass = housekeeping_pass_with(ctx.pool(), ctx.keys(), now(), |event| async move {
        crate::publish::send_event_first_ack(client, &event, |_| {}).await
    })
    .await;
    if let Err(e) = pass {
        tracing::warn!("lease housekeeping: pass ended early ({e}); the next one continues");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::context::test_utils::{test_settings, TestContextBuilder};
    use mostro_core::lease::LeaseContract;
    use mostro_core::lease_message::{LeaseChannel, LeaseInvoice, LeasePreimage, LeaseTake};
    use mostro_core::node_binding::{
        sign_ln_message, Action as BindingAction, Network, SignedStatement, Statement,
    };
    use nostr_sdk::prelude::{FinalizeEvent, Keys, Timestamp};
    use secp256k1::{Secp256k1, SecretKey};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;

    /// A node runner: an identity key, a trade key, and a node key the identity is bound to.
    struct Party {
        identity: Keys,
        trade: Keys,
        node: SecretKey,
    }

    impl Party {
        fn new() -> Self {
            // Any 32 random bytes that make a valid key; a fresh Nostr key is a handy source.
            let node =
                SecretKey::from_slice(&Keys::generate().secret_key().to_secret_bytes()).unwrap();
            Party {
                identity: Keys::generate(),
                trade: Keys::generate(),
                node,
            }
        }

        fn node_key(&self) -> secp256k1::PublicKey {
            secp256k1::PublicKey::from_secret_key(&Secp256k1::signing_only(), &self.node)
        }

        /// This node's binding of `identity`, dated `at`.
        fn binding_of(&self, identity: &Keys, at: u64) -> String {
            let statement = Statement::new(
                BindingAction::Bind,
                Network::Regtest,
                &identity.public_key().to_hex(),
                self.node_key(),
                at,
            )
            .unwrap();
            let node_signature = sign_ln_message(statement.text().as_bytes(), &self.node);
            SignedStatement {
                statement,
                node_signature,
            }
            .to_event_builder()
            .finalize(identity)
            .unwrap()
            .as_json()
        }

        fn binding(&self) -> String {
            self.binding_of(&self.identity, now() - 60)
        }

        fn offer(&self) -> LeaseOffer {
            LeaseOffer {
                network: Network::Regtest,
                seller_node: self.node_key().to_string(),
                binding: self.binding(),
                min_capacity_sat: 1_000_000,
                max_capacity_sat: 5_000_000,
                duration_blocks: 4_320,
                fee_base_sat: 1_000,
                fee_ppm: 2_500,
                upfront_percent: 50,
                min_confirmations: 3,
                announce: true,
                expires_at: now() + 86_400,
            }
        }

        /// This party's contract for `offer` at `capacity_sat`.
        fn contract(&self, offer: &LeaseOffer, capacity_sat: u64) -> LeaseContract {
            LeaseContract {
                network: offer.network,
                seller_node: offer.seller_node_key().unwrap(),
                buyer_node: self.node_key(),
                terms: offer.terms_for(capacity_sat).unwrap(),
                payment_hash: "ab".repeat(32),
                created_at: now(),
            }
        }

        fn take(&self, contract: &LeaseContract) -> LeaseTake {
            LeaseTake {
                contract: contract.text(),
                binding: self.binding(),
                node_address: Some("203.0.113.7:9735".into()),
            }
        }

        /// Sends one lease action as this party and returns the handler's verdict.
        async fn send(
            &self,
            ctx: &AppContext,
            id: Option<Uuid>,
            action: Action,
            payload: Option<LeasePayload>,
        ) -> Result<(), MostroError> {
            let msg = Message::new_order(
                id,
                Some(7),
                None,
                action.clone(),
                payload.map(Payload::Lease),
            );
            assert!(msg.verify(), "the test sends only well-formed messages");
            let event = UnwrappedMessage {
                message: msg.clone(),
                signature: None,
                sender: self.trade.public_key(),
                identity: self.identity.public_key(),
                created_at: Timestamp::now(),
            };
            if action == Action::Cancel {
                assert!(names_a_lease(ctx, &msg).await);
                return lease_cancel_action(ctx, msg, &event).await;
            }
            lease_action(ctx, &action, msg, &event).await
        }

        /// The messages queued for this party's trade key, oldest first.
        async fn inbox(&self) -> Vec<MessageKind> {
            crate::config::MESSAGE_QUEUES
                .queue_order_msg
                .read()
                .await
                .iter()
                .filter(|(_, pk)| *pk == self.trade.public_key())
                .map(|(m, _)| m.get_inner_message_kind().clone())
                .collect()
        }
    }

    async fn ctx() -> AppContext {
        let _ = crate::config::MOSTRO_CONFIG.set(test_settings());
        // One connection: an in-memory SQLite database is per connection.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        TestContextBuilder::new()
            .with_pool(Arc::new(pool))
            .with_settings(test_settings())
            .build()
    }

    fn refused(result: Result<(), MostroError>) -> CantDoReason {
        match result {
            Err(MostroCantDo(reason)) => reason,
            other => panic!("expected a cant-do, got {other:?}"),
        }
    }

    async fn status(ctx: &AppContext, id: Uuid) -> String {
        offer_by_id(ctx.pool(), id).await.unwrap().unwrap().status
    }

    /// The seller's offer is stored; returns its order id.
    async fn offered(ctx: &AppContext, seller: &Party) -> (Uuid, LeaseOffer) {
        let offer = seller.offer();
        seller
            .send(
                ctx,
                None,
                Action::LeaseOffer,
                Some(LeasePayload::Offer(offer.clone())),
            )
            .await
            .unwrap();
        let echo = seller.inbox().await.pop().unwrap();
        assert_eq!(echo.action, Action::LeaseOffer);
        assert_eq!(echo.request_id, Some(7));
        (echo.id.unwrap(), offer)
    }

    /// Offer and take; returns the order id and the contract.
    async fn taken(ctx: &AppContext, seller: &Party, buyer: &Party) -> (Uuid, LeaseContract) {
        let (id, offer) = offered(ctx, seller).await;
        let contract = buyer.contract(&offer, 2_000_000);
        buyer
            .send(
                ctx,
                Some(id),
                Action::TakeLease,
                Some(LeasePayload::Take(buyer.take(&contract))),
            )
            .await
            .unwrap();
        (id, contract)
    }

    fn invoice(contract: &LeaseContract) -> LeasePayload {
        LeasePayload::Invoice(LeaseInvoice {
            lease_id: contract.id(),
            invoice: format!("lnbcrt30u1{}", "q".repeat(200)),
        })
    }

    fn channel(contract: &LeaseContract) -> LeasePayload {
        LeasePayload::Channel(LeaseChannel {
            lease_id: contract.id(),
            funding_txid: "cd".repeat(32),
            output_index: 1,
        })
    }

    #[tokio::test]
    async fn a_lease_is_relayed_step_by_step_from_offer_to_completion() {
        let ctx = ctx().await;
        let (seller, buyer) = (Party::new(), Party::new());
        let (id, contract) = taken(&ctx, &seller, &buyer).await;
        assert_eq!(status(&ctx, id).await, TAKEN);

        // The seller gets the take and the buyer's trade key; the buyer gets the seller's.
        let to_seller = seller.inbox().await;
        assert_eq!(to_seller.len(), 3, "offer echo, take, buyer's trade key");
        assert_eq!(to_seller[1].action, Action::TakeLease);
        assert_eq!(to_seller[1].id, Some(id));
        match &to_seller[1].payload {
            Some(Payload::Lease(LeasePayload::Take(take))) => {
                assert_eq!(take.contract, contract.text())
            }
            other => panic!("unexpected payload {other:?}"),
        }
        let peer_key = |kind: &MessageKind| match &kind.payload {
            Some(Payload::Peer(peer)) => peer.pubkey.clone(),
            other => panic!("unexpected payload {other:?}"),
        };
        assert_eq!(to_seller[2].action, Action::TradePubkey);
        assert_eq!(peer_key(&to_seller[2]), buyer.trade.public_key().to_hex());
        let to_buyer = buyer.inbox().await;
        assert_eq!(to_buyer.len(), 1);
        assert_eq!(to_buyer[0].action, Action::TradePubkey);
        assert_eq!(peer_key(&to_buyer[0]), seller.trade.public_key().to_hex());

        let steps = [
            (Action::LeaseInvoice, Some(invoice(&contract)), INVOICED),
            (Action::LeaseChannelOpened, Some(channel(&contract)), OPENED),
            (Action::LeaseActive, None, ACTIVE),
            (
                Action::LeaseCompletionInvoice,
                Some(invoice(&contract)),
                COMPLETION,
            ),
        ];
        for (n, (action, payload, state)) in steps.into_iter().enumerate() {
            seller
                .send(&ctx, Some(id), action.clone(), payload.clone())
                .await
                .unwrap();
            assert_eq!(status(&ctx, id).await, state);
            let to_buyer = buyer.inbox().await;
            assert_eq!(to_buyer.len(), n + 2);
            let relayed = to_buyer.last().unwrap();
            assert_eq!(
                (relayed.action.clone(), relayed.id),
                (action.clone(), Some(id))
            );
            match (&relayed.payload, &payload) {
                (Some(Payload::Lease(got)), Some(sent)) => assert_eq!(got, sent),
                (None, None) => {}
                other => panic!("relayed payload differs: {other:?}"),
            }
            // A repeat changes nothing and relays nothing.
            assert_eq!(
                refused(seller.send(&ctx, Some(id), action, payload).await),
                CantDoReason::NotAllowedByStatus
            );
            assert_eq!(buyer.inbox().await.len(), n + 2);
        }

        let row = sqlx::query("SELECT funding_txid, output_index FROM leases WHERE offer_id = ?")
            .bind(id.to_string())
            .fetch_one(ctx.pool())
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("funding_txid"), "cd".repeat(32));
        assert_eq!(row.get::<i64, _>("output_index"), 1);
    }

    #[tokio::test]
    async fn an_offer_needs_valid_terms_a_sane_lifetime_and_the_senders_own_binding() {
        let ctx = ctx().await;
        let seller = Party::new();
        let send = |offer: LeaseOffer| {
            let (ctx, seller) = (&ctx, &seller);
            async move {
                seller
                    .send(
                        ctx,
                        None,
                        Action::LeaseOffer,
                        Some(LeasePayload::Offer(offer)),
                    )
                    .await
            }
        };
        let good = seller.offer();

        let mut zero_split = good.clone();
        zero_split.upfront_percent = 0;
        assert_eq!(
            refused(send(zero_split).await),
            CantDoReason::InvalidParameters
        );
        let mut expired = good.clone();
        expired.expires_at = now() - 1;
        assert_eq!(
            refused(send(expired).await),
            CantDoReason::InvalidParameters
        );
        let mut forever = good.clone();
        forever.expires_at = now() + MAX_OFFER_LIFETIME_SECS + 3600;
        assert_eq!(
            refused(send(forever).await),
            CantDoReason::InvalidParameters
        );

        // A binding of the node to someone else's key does not make the sender its operator.
        let other = Keys::generate();
        let mut borrowed = good.clone();
        borrowed.binding = seller.binding_of(&other, now() - 60);
        assert_eq!(refused(send(borrowed).await), CantDoReason::NotAuthorized);
        // Nor does naming a node whose binding the sender does not hold.
        let mut other_node = good.clone();
        other_node.seller_node = Party::new().node_key().to_string();
        assert_eq!(refused(send(other_node).await), CantDoReason::NotAuthorized);

        // An offer with an id is not a new offer.
        assert_eq!(
            refused(
                seller
                    .send(
                        &ctx,
                        Some(Uuid::new_v4()),
                        Action::LeaseOffer,
                        Some(LeasePayload::Offer(good.clone()))
                    )
                    .await
            ),
            CantDoReason::InvalidParameters
        );
        assert!(seller.inbox().await.is_empty());
        let stored: i64 = sqlx::query("SELECT COUNT(*) AS n FROM lease_offers")
            .fetch_one(ctx.pool())
            .await
            .unwrap()
            .get("n");
        assert_eq!(stored, 0);

        assert!(send(good).await.is_ok());
    }

    #[tokio::test]
    async fn one_identity_can_only_hold_so_many_open_offers() {
        let ctx = ctx().await;
        let seller = Party::new();
        for _ in 0..MAX_OPEN_OFFERS_PER_SELLER {
            offered(&ctx, &seller).await;
        }
        let one_more = seller
            .send(
                &ctx,
                None,
                Action::LeaseOffer,
                Some(LeasePayload::Offer(seller.offer())),
            )
            .await;
        assert_eq!(refused(one_more), CantDoReason::TooManyRequests);
    }

    #[tokio::test]
    async fn a_take_must_be_the_offer_at_its_price_from_a_bound_buyer() {
        let ctx = ctx().await;
        let (seller, buyer) = (Party::new(), Party::new());
        let (id, offer) = offered(&ctx, &seller).await;
        let good = buyer.contract(&offer, 2_000_000);
        let take = |party: &Party, contract: &LeaseContract| {
            Some(LeasePayload::Take(party.take(contract)))
        };

        let unknown = buyer
            .send(
                &ctx,
                Some(Uuid::new_v4()),
                Action::TakeLease,
                take(&buyer, &good),
            )
            .await;
        assert_eq!(refused(unknown), CantDoReason::NotFound);

        let mut cheaper = good.clone();
        cheaper.terms.fee_ppm = 1;
        let mut too_big = good.clone();
        too_big.terms.capacity_sat = 5_000_001;
        let mut stale = good.clone();
        stale.created_at = now() - MAX_CONTRACT_AGE_SECS - 60;
        let mut future = good.clone();
        future.created_at = now() + MAX_CONTRACT_FUTURE_SECS + 60;
        for contract in [cheaper, too_big, stale, future] {
            let result = buyer
                .send(&ctx, Some(id), Action::TakeLease, take(&buyer, &contract))
                .await;
            assert_eq!(refused(result), CantDoReason::InvalidParameters);
        }

        // The buyer's binding must be of the contract's buyer node to the sender's identity.
        let stranger = Party::new();
        let with_others_binding = LeaseTake {
            binding: stranger.binding(),
            ..buyer.take(&good)
        };
        let result = buyer
            .send(
                &ctx,
                Some(id),
                Action::TakeLease,
                Some(LeasePayload::Take(with_others_binding)),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::NotAuthorized);

        // A seller cannot take its own offer, even with a second node.
        let second_node = Party {
            identity: seller.identity.clone(),
            trade: Keys::generate(),
            node: Party::new().node,
        };
        let own = second_node.contract(&offer, 2_000_000);
        let result = second_node
            .send(&ctx, Some(id), Action::TakeLease, take(&second_node, &own))
            .await;
        assert_eq!(refused(result), CantDoReason::InvalidPubkey);

        assert_eq!(status(&ctx, id).await, PENDING);
        assert!(buyer.inbox().await.is_empty());
        assert_eq!(seller.inbox().await.len(), 1, "only the offer echo");

        // The first valid take wins; the offer is then closed to everyone else.
        buyer
            .send(&ctx, Some(id), Action::TakeLease, take(&buyer, &good))
            .await
            .unwrap();
        let late = stranger.contract(&offer, 3_000_000);
        let result = stranger
            .send(&ctx, Some(id), Action::TakeLease, take(&stranger, &late))
            .await;
        assert_eq!(refused(result), CantDoReason::NotAllowedByStatus);
        assert!(stranger.inbox().await.is_empty());
    }

    #[tokio::test]
    async fn one_contract_cannot_take_two_offers() {
        let ctx = ctx().await;
        let (seller, buyer) = (Party::new(), Party::new());
        let (first, offer) = offered(&ctx, &seller).await;
        let (second, _) = offered(&ctx, &seller).await;
        let contract = buyer.contract(&offer, 2_000_000);
        let take = || Some(LeasePayload::Take(buyer.take(&contract)));
        buyer
            .send(&ctx, Some(first), Action::TakeLease, take())
            .await
            .unwrap();
        let result = buyer
            .send(&ctx, Some(second), Action::TakeLease, take())
            .await;
        assert_eq!(refused(result), CantDoReason::InvalidParameters);
        // The second offer stays open for a buyer with a contract of its own.
        assert_eq!(status(&ctx, second).await, PENDING);
        assert_eq!(status(&ctx, first).await, TAKEN);
    }

    #[tokio::test]
    async fn only_the_seller_advances_a_lease_in_order_and_for_its_own_lease_id() {
        let ctx = ctx().await;
        let (seller, buyer, stranger) = (Party::new(), Party::new(), Party::new());
        let (id, contract) = taken(&ctx, &seller, &buyer).await;
        let before = buyer.inbox().await.len();

        for other in [&buyer, &stranger] {
            let result = other
                .send(
                    &ctx,
                    Some(id),
                    Action::LeaseInvoice,
                    Some(invoice(&contract)),
                )
                .await;
            assert_eq!(refused(result), CantDoReason::IsNotYourOrder);
        }
        // Out of order: no channel report or activation before the invoice.
        let result = seller
            .send(
                &ctx,
                Some(id),
                Action::LeaseChannelOpened,
                Some(channel(&contract)),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::NotAllowedByStatus);
        let result = seller.send(&ctx, Some(id), Action::LeaseActive, None).await;
        assert_eq!(refused(result), CantDoReason::NotAllowedByStatus);
        // An invoice for another lease id.
        let other_lease = LeasePayload::Invoice(LeaseInvoice {
            lease_id: "ef".repeat(32),
            invoice: format!("lnbcrt30u1{}", "q".repeat(200)),
        });
        let result = seller
            .send(&ctx, Some(id), Action::LeaseInvoice, Some(other_lease))
            .await;
        assert_eq!(refused(result), CantDoReason::InvalidParameters);
        // Something that is not an invoice.
        let junk = LeasePayload::Invoice(LeaseInvoice {
            lease_id: contract.id(),
            invoice: "not an invoice".into(),
        });
        let result = seller
            .send(&ctx, Some(id), Action::LeaseInvoice, Some(junk))
            .await;
        assert_eq!(refused(result), CantDoReason::InvalidInvoice);
        // A seller step on an offer nobody took.
        let (untaken, _) = offered(&ctx, &seller).await;
        let result = seller
            .send(
                &ctx,
                Some(untaken),
                Action::LeaseInvoice,
                Some(invoice(&contract)),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::NotAllowedByStatus);

        assert_eq!(status(&ctx, id).await, TAKEN);
        assert_eq!(buyer.inbox().await.len(), before, "nothing was relayed");
    }

    #[tokio::test]
    async fn the_instance_refuses_the_preimage_and_keeps_no_trace_of_it() {
        let ctx = ctx().await;
        let (seller, buyer) = (Party::new(), Party::new());
        let (id, contract) = taken(&ctx, &seller, &buyer).await;
        let secret = "5a".repeat(32);
        let before = (seller.inbox().await.len(), buyer.inbox().await.len());

        let result = buyer
            .send(
                &ctx,
                Some(id),
                Action::LeasePreimage,
                Some(LeasePayload::Preimage(LeasePreimage {
                    lease_id: contract.id(),
                    preimage: secret.clone(),
                })),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::InvalidAction);
        assert_eq!(status(&ctx, id).await, TAKEN);
        assert_eq!(
            (seller.inbox().await.len(), buyer.inbox().await.len()),
            before
        );

        // Every text column of both lease tables, for every row.
        for table in ["lease_offers", "leases"] {
            let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT * FROM {table}")))
                .fetch_all(ctx.pool())
                .await
                .unwrap();
            assert!(!rows.is_empty());
            for row in rows {
                for column in 0..row.len() {
                    if let Ok(Some(text)) = row.try_get::<Option<String>, _>(column) {
                        assert!(!text.contains(&secret), "{table} column {column}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn either_party_can_cancel_before_the_lease_is_active_and_the_other_is_told() {
        let ctx = ctx().await;
        let (seller, buyer, stranger) = (Party::new(), Party::new(), Party::new());
        let last = |inbox: Vec<MessageKind>| inbox.last().map(|k| (k.action.clone(), k.id));

        // The seller withdraws an offer nobody took.
        let (open, _) = offered(&ctx, &seller).await;
        let result = stranger.send(&ctx, Some(open), Action::Cancel, None).await;
        assert_eq!(refused(result), CantDoReason::IsNotYourOrder);
        seller
            .send(&ctx, Some(open), Action::Cancel, None)
            .await
            .unwrap();
        assert_eq!(status(&ctx, open).await, CANCELED);
        assert_eq!(
            last(seller.inbox().await),
            Some((Action::Canceled, Some(open)))
        );
        let again = seller.send(&ctx, Some(open), Action::Cancel, None).await;
        assert_eq!(refused(again), CantDoReason::OrderAlreadyCanceled);
        // A canceled offer cannot be taken.
        let offer = seller.offer();
        let contract = buyer.contract(&offer, 2_000_000);
        let result = buyer
            .send(
                &ctx,
                Some(open),
                Action::TakeLease,
                Some(LeasePayload::Take(buyer.take(&contract))),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::NotAllowedByStatus);

        // The buyer backs out after the invoice; the seller is told.
        let (id, contract) = taken(&ctx, &seller, &buyer).await;
        seller
            .send(
                &ctx,
                Some(id),
                Action::LeaseInvoice,
                Some(invoice(&contract)),
            )
            .await
            .unwrap();
        buyer
            .send(&ctx, Some(id), Action::Cancel, None)
            .await
            .unwrap();
        assert_eq!(status(&ctx, id).await, CANCELED);
        assert_eq!(
            last(buyer.inbox().await),
            Some((Action::Canceled, Some(id)))
        );
        assert_eq!(
            last(seller.inbox().await),
            Some((Action::Canceled, Some(id)))
        );
        // A canceled lease takes no further steps.
        let result = seller
            .send(
                &ctx,
                Some(id),
                Action::LeaseChannelOpened,
                Some(channel(&contract)),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::NotAllowedByStatus);

        // An active lease cannot be canceled by either side.
        let (seller, buyer) = (Party::new(), Party::new());
        let (id, contract) = taken(&ctx, &seller, &buyer).await;
        for (action, payload) in [
            (Action::LeaseInvoice, Some(invoice(&contract))),
            (Action::LeaseChannelOpened, Some(channel(&contract))),
            (Action::LeaseActive, None),
        ] {
            seller.send(&ctx, Some(id), action, payload).await.unwrap();
        }
        for party in [&seller, &buyer] {
            let result = party.send(&ctx, Some(id), Action::Cancel, None).await;
            assert_eq!(refused(result), CantDoReason::NotAllowedByStatus);
        }
        assert_eq!(status(&ctx, id).await, ACTIVE);
    }

    type Sent = Arc<std::sync::Mutex<Vec<Event>>>;

    /// A `send` that keeps what it is given, or refuses everything.
    fn sender(
        sent: &Sent,
        works: bool,
    ) -> impl FnMut(Event) -> std::future::Ready<Result<(), MostroError>> {
        let sent = sent.clone();
        move |event| {
            std::future::ready(if works {
                sent.lock().unwrap().push(event);
                Ok(())
            } else {
                Err(MostroInternalErr(ServiceError::NostrError(
                    "no relay".into(),
                )))
            })
        }
    }

    /// One sync of `id` at `at`: what it did and the events it sent.
    async fn sync_at(ctx: &AppContext, id: Uuid, at: u64) -> (OrderSync, Vec<LeaseOrder>) {
        let sent = Sent::default();
        let outcome = sync_order_event_with(ctx.pool(), ctx.keys(), id, at, sender(&sent, true))
            .await
            .unwrap();
        (outcome, orders(ctx, &sent))
    }

    /// The orders in `sent`, each a valid event signed by the instance.
    fn orders(ctx: &AppContext, sent: &Sent) -> Vec<LeaseOrder> {
        sent.lock()
            .unwrap()
            .iter()
            .map(|event| {
                assert_eq!(event.pubkey, ctx.keys().public_key());
                LeaseOrder::from_event(event).unwrap()
            })
            .collect()
    }

    async fn pass_at(ctx: &AppContext, at: u64) -> Vec<LeaseOrder> {
        let sent = Sent::default();
        housekeeping_pass_with(ctx.pool(), ctx.keys(), at, sender(&sent, true))
            .await
            .unwrap();
        orders(ctx, &sent)
    }

    async fn synced(ctx: &AppContext, id: Uuid) -> (Option<String>, Option<i64>) {
        let row =
            sqlx::query("SELECT synced_status, order_event_at FROM lease_offers WHERE id = ?")
                .bind(id.to_string())
                .fetch_one(ctx.pool())
                .await
                .unwrap();
        (row.get("synced_status"), row.get("order_event_at"))
    }

    // The handlers also try to publish, on a client with no relay: that fails at once and
    // leaves the row behind, which is where each of these tests starts.

    #[tokio::test]
    async fn the_order_event_follows_the_lease_and_is_only_sent_when_it_changes() {
        let ctx = ctx().await;
        let (seller, buyer) = (Party::new(), Party::new());
        let (id, offer) = offered(&ctx, &seller).await;
        assert_eq!(synced(&ctx, id).await, (None, None));
        let t = now();

        // A relay that refuses leaves the row behind for the next try.
        let refused = sync_order_event_with(
            ctx.pool(),
            ctx.keys(),
            id,
            t,
            sender(&Sent::default(), false),
        )
        .await;
        assert!(refused.is_err());
        assert_eq!(synced(&ctx, id).await, (None, None));

        let (outcome, sent) = sync_at(&ctx, id, t).await;
        assert_eq!(outcome, OrderSync::Published);
        assert_eq!(
            sent,
            vec![LeaseOrder::from_offer(id, LeaseOrderStatus::Pending, &offer).unwrap()]
        );
        assert!(sent[0].is_open(t));
        assert_eq!(
            synced(&ctx, id).await,
            (Some(PENDING.to_string()), Some(t as i64))
        );
        assert_eq!(sync_at(&ctx, id, t).await, (OrderSync::Current, vec![]));

        // Taken within the same second: the new event is still dated after the last one.
        let contract = buyer.contract(&offer, 2_000_000);
        buyer
            .send(
                &ctx,
                Some(id),
                Action::TakeLease,
                Some(LeasePayload::Take(buyer.take(&contract))),
            )
            .await
            .unwrap();
        let (outcome, sent) = sync_at(&ctx, id, t).await;
        assert_eq!(outcome, OrderSync::Published);
        assert_eq!(sent[0].status, LeaseOrderStatus::InProgress);
        assert_eq!(
            synced(&ctx, id).await,
            (Some(TAKEN.to_string()), Some(t as i64 + 1))
        );

        // Steps that do not change the public status send nothing.
        let steps = [
            (Action::LeaseInvoice, Some(invoice(&contract)), None),
            (Action::LeaseChannelOpened, Some(channel(&contract)), None),
            (Action::LeaseActive, None, Some(LeaseOrderStatus::Success)),
            (
                Action::LeaseCompletionInvoice,
                Some(invoice(&contract)),
                None,
            ),
        ];
        for (action, payload, published) in steps {
            seller.send(&ctx, Some(id), action, payload).await.unwrap();
            let (outcome, sent) = sync_at(&ctx, id, t).await;
            match published {
                Some(status) => {
                    assert_eq!(outcome, OrderSync::Published);
                    assert_eq!(sent.len(), 1);
                    assert_eq!(sent[0].status, status);
                }
                // The handler itself already marked the row up to date, sending nothing.
                None => assert_eq!((outcome, sent), (OrderSync::Current, vec![])),
            }
            assert_eq!(synced(&ctx, id).await.0, Some(status(&ctx, id).await));
        }
        assert_eq!(synced(&ctx, id).await.1, Some(t as i64 + 2));
    }

    #[tokio::test]
    async fn nothing_is_sent_for_an_order_relays_never_saw_or_have_dropped() {
        let ctx = ctx().await;
        let seller = Party::new();

        // Withdrawn before its first publish: no ghost `canceled` order.
        let (never_seen, _) = offered(&ctx, &seller).await;
        seller
            .send(&ctx, Some(never_seen), Action::Cancel, None)
            .await
            .unwrap();
        assert_eq!(
            synced(&ctx, never_seen).await,
            (Some(CANCELED.to_string()), None)
        );
        assert_eq!(
            sync_at(&ctx, never_seen, now()).await,
            (OrderSync::Current, vec![])
        );

        // Published, then withdrawn: relays are told.
        let (seen, offer) = offered(&ctx, &seller).await;
        assert_eq!(sync_at(&ctx, seen, now()).await.0, OrderSync::Published);
        seller
            .send(&ctx, Some(seen), Action::Cancel, None)
            .await
            .unwrap();
        let (outcome, sent) = sync_at(&ctx, seen, now()).await;
        assert_eq!(outcome, OrderSync::Published);
        assert_eq!(sent[0].status, LeaseOrderStatus::Canceled);

        // Published, then withdrawn after its expiry: relays dropped the event at the expiry
        // it carries and would refuse a new one.
        let (late, _) = offered(&ctx, &seller).await;
        assert_eq!(sync_at(&ctx, late, now()).await.0, OrderSync::Published);
        seller
            .send(&ctx, Some(late), Action::Cancel, None)
            .await
            .unwrap();
        assert_eq!(
            sync_at(&ctx, late, offer.expires_at + 60).await,
            (OrderSync::Skipped, vec![])
        );
        assert_eq!(synced(&ctx, late).await.0, Some(CANCELED.to_string()));
    }

    #[tokio::test]
    async fn housekeeping_expires_untaken_offers_cancels_stalled_leases_and_catches_up() {
        let ctx = ctx().await;
        let (seller, buyer) = (Party::new(), Party::new());
        let t = now();
        let last = |inbox: Vec<MessageKind>| inbox.last().map(|k| (k.action.clone(), k.id));

        let (open, offer) = offered(&ctx, &seller).await;
        let (stalled, _) = taken(&ctx, &seller, &buyer).await;
        let (live_seller, live_buyer) = (Party::new(), Party::new());
        let (live, contract) = taken(&ctx, &live_seller, &live_buyer).await;
        for (action, payload) in [
            (Action::LeaseInvoice, Some(invoice(&contract))),
            (Action::LeaseChannelOpened, Some(channel(&contract))),
            (Action::LeaseActive, None),
        ] {
            live_seller
                .send(&ctx, Some(live), action, payload)
                .await
                .unwrap();
        }

        // A pass now changes no state and publishes the three orders that are behind.
        let mut sent: Vec<_> = pass_at(&ctx, t)
            .await
            .into_iter()
            .map(|order| (order.id, order.status))
            .collect();
        sent.sort_by_key(|(id, _)| *id);
        let mut expected = vec![
            (open, LeaseOrderStatus::Pending),
            (stalled, LeaseOrderStatus::InProgress),
            (live, LeaseOrderStatus::Success),
        ];
        expected.sort_by_key(|(id, _)| *id);
        assert_eq!(sent, expected);
        assert_eq!(status(&ctx, open).await, PENDING);
        assert_eq!(status(&ctx, stalled).await, TAKEN);
        assert!(pass_at(&ctx, t).await.is_empty(), "nothing is behind now");

        // An hour on, a lease still within its setup window is left alone.
        assert!(pass_at(&ctx, t + 3600).await.is_empty());
        assert_eq!(status(&ctx, stalled).await, TAKEN);

        // Past the offer's expiry: the untaken offer expires; nothing is sent for it.
        assert!(pass_at(&ctx, offer.expires_at).await.is_empty());
        assert_eq!(status(&ctx, open).await, EXPIRED);
        assert_eq!(synced(&ctx, open).await.0, Some(EXPIRED.to_string()));
        assert_eq!(status(&ctx, stalled).await, TAKEN);
        // An expired offer cannot be taken, whatever clock the taker goes by.
        let late = buyer.contract(&offer, 2_000_000);
        let result = buyer
            .send(
                &ctx,
                Some(open),
                Action::TakeLease,
                Some(LeasePayload::Take(buyer.take(&late))),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::NotAllowedByStatus);

        // Past the setup window: the stalled lease is canceled and both parties are told; the
        // active one is not touched.
        let before = (seller.inbox().await.len(), buyer.inbox().await.len());
        assert!(pass_at(&ctx, t + LEASE_SETUP_TIMEOUT_SECS + 60)
            .await
            .is_empty());
        assert_eq!(status(&ctx, stalled).await, CANCELED);
        assert_eq!(status(&ctx, live).await, ACTIVE);
        assert_eq!(
            last(seller.inbox().await),
            Some((Action::Canceled, Some(stalled)))
        );
        assert_eq!(
            last(buyer.inbox().await),
            Some((Action::Canceled, Some(stalled)))
        );
        assert_eq!(
            (seller.inbox().await.len(), buyer.inbox().await.len()),
            (before.0 + 1, before.1 + 1)
        );
        // A second pass tells nobody again.
        pass_at(&ctx, t + LEASE_SETUP_TIMEOUT_SECS + 120).await;
        assert_eq!(
            (seller.inbox().await.len(), buyer.inbox().await.len()),
            (before.0 + 1, before.1 + 1)
        );
    }

    #[tokio::test]
    async fn housekeeping_stops_at_the_first_refusal_and_resumes_later() {
        let ctx = ctx().await;
        let seller = Party::new();
        let (first, _) = offered(&ctx, &seller).await;
        let (second, _) = offered(&ctx, &seller).await;

        let result = housekeeping_pass_with(
            ctx.pool(),
            ctx.keys(),
            now(),
            sender(&Sent::default(), false),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(synced(&ctx, first).await.0, None);
        assert_eq!(synced(&ctx, second).await.0, None);

        assert_eq!(pass_at(&ctx, now()).await.len(), 2);
    }

    #[tokio::test]
    async fn maintenance_mode_takes_no_new_offers_or_takes_but_lets_leases_finish() {
        let ctx = ctx().await;
        let (seller, buyer) = (Party::new(), Party::new());
        let (open, offer) = offered(&ctx, &seller).await;
        let (id, contract) = taken(&ctx, &seller, &buyer).await;
        ctx.maintenance().set(ctx.pool(), true, None).await.unwrap();

        let result = seller
            .send(
                &ctx,
                None,
                Action::LeaseOffer,
                Some(LeasePayload::Offer(seller.offer())),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::MaintenanceMode);
        let other = buyer.contract(&offer, 2_000_000);
        let result = buyer
            .send(
                &ctx,
                Some(open),
                Action::TakeLease,
                Some(LeasePayload::Take(buyer.take(&other))),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::MaintenanceMode);
        assert_eq!(status(&ctx, open).await, PENDING);

        // A lease already under way goes on, and can still be canceled.
        seller
            .send(
                &ctx,
                Some(id),
                Action::LeaseInvoice,
                Some(invoice(&contract)),
            )
            .await
            .unwrap();
        assert_eq!(status(&ctx, id).await, INVOICED);
        seller
            .send(&ctx, Some(open), Action::Cancel, None)
            .await
            .unwrap();
        assert_eq!(status(&ctx, open).await, CANCELED);
    }

    #[tokio::test]
    async fn an_order_id_that_is_not_a_lease_stays_on_the_escrow_path() {
        let ctx = ctx().await;
        let fiat_cancel =
            Message::new_order(Some(Uuid::new_v4()), None, None, Action::Cancel, None);
        assert!(!names_a_lease(&ctx, &fiat_cancel).await);
        let no_id = Message::new_order(None, None, None, Action::Cancel, None);
        assert!(!names_a_lease(&ctx, &no_id).await);
    }
}
