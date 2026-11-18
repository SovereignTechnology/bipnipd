//! bipnip: liquidity ring coordination (bipnip repo, `docs/nips/liquidity-rings.md`).
//!
//! The instance fills a ring's slots, fixes the order of its members, collects their commits and
//! relays their channel reports. No channel money moves through it: every member opens a channel
//! from its own node to the next member. The one thing it may hold is a bond, when the ring asks
//! for one (below, and `app::liquidity_bond`).
//!
//! A ring's state lives in `ring_offers.status`:
//!
//! ```text
//! pending -> committing -> [bonding ->] open -> success
//!    |            \             \          \----> partial     (the window ended)
//!    |             \             \-> canceled               (a bond was not paid)
//!    |              \-> partial                             (the window ended)
//!    \-> canceled | expired
//! ```
//!
//! - `pending`: slots are open. The count of taken slots changes by compare-and-swap, so a ring
//!   never has more members than slots.
//! - `committing`: the last slot was taken; the order of the members was drawn at random and the
//!   roster sent to all of them. Each must sign the ring id.
//! - `open`: every member has committed; all commits were sent to all members. Members open
//!   their channel and report it; the member opened to confirms.
//! - `success`: every channel was confirmed. `partial`: the window ended first.
//! - `bonding` (rings with a bond only): every member has committed and was sent a hold invoice
//!   on this instance's node for the bond. Nobody is told to open until every bond is locked. A
//!   bond not paid within the hour cancels the ring, and the bonds already locked go back.
//!
//! **Bonds.** When every channel is confirmed, every bond goes back. When the window ends first,
//! each member's bond is decided on its own: it goes back if the member it opened to confirmed
//! the channel, or if **this instance's own node** sees that channel in the public graph (a new
//! channel of the ring's capacity between the two nodes, the one the member reported if it
//! reported one, and not one another member reported). Otherwise the bond is taken and owed to
//! the member it should have opened to, who claims it with an invoice. So a member's word alone
//! never takes another member's bond, and a member that opened is safe from a neighbour that
//! denies it. While the node cannot be asked, nothing is decided.
//!
//! What the instance vouches for is small on purpose. Members check the roster, every binding in
//! it and every commit themselves, and a channel counts only when the member it was opened to
//! says its own node sees it. The instance records an opener's report as a claim.
//!
//! Each ring has a public order event (kind 38735, `k` = `ring`) with its status and how many
//! slots are taken; it names no member. Publishing follows the same rules as for leases.

use crate::app::context::AppContext;
use crate::app::liquidity_bond::{self, BOND_PAY_WINDOW_SECS, RING};
use crate::app::liquidity_outcome;
use crate::app::liquidity_vet::{self, Candidate};
use crate::util::enqueue_order_msg;
use bipnip_ln::LightningBackend;
use mostro_core::bond::bond_cltv_delta;
use mostro_core::outcome::{Deal, OutcomeResult};
use mostro_core::prelude::*;
use mostro_core::ring::Ring;
use mostro_core::ring_message::{
    RingClosed, RingCommitment, RingInvoice, RingMessageError, RingOffer, RingOpen, RingPayload,
    RingRoster, RingSeat,
};
use mostro_core::ring_order::{RingOrder, RingOrderStatus};
use nostr_sdk::prelude::{Event, FinalizeEvent, Keys, PublicKey, Timestamp};
use rand::seq::SliceRandom;
use sqlx::{Row, SqlitePool};
use std::future::Future;
use uuid::Uuid;

/// Most rings one identity may have open for slots at a time.
const MAX_OPEN_RINGS_PER_CREATOR: i64 = 5;
/// Longest a ring may wait for its slots to fill: 30 days.
const MAX_OFFER_LIFETIME_SECS: u64 = 30 * 24 * 3600;
/// Most order events one housekeeping pass brings up to date.
const MAX_ORDER_EVENTS_PER_PASS: i64 = 100;

const PENDING: &str = "pending";
const COMMITTING: &str = "committing";
const BONDING: &str = "bonding";
const OPEN: &str = "open";
const SUCCESS: &str = "success";
const PARTIAL: &str = "partial";
const CANCELED: &str = "canceled";
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

fn broken(what: &str) -> MostroError {
    MostroInternalErr(ServiceError::UnexpectedError(what.to_string()))
}

fn stored_key(hex: &str) -> Result<PublicKey, MostroError> {
    PublicKey::parse(hex).map_err(|_| MostroInternalErr(ServiceError::InvalidPubkey))
}

/// A ring row.
struct Offer {
    creator_identity: String,
    offer: RingOffer,
    status: String,
    ring: Option<String>,
    window_ends_at: Option<i64>,
}

impl Offer {
    /// The fixed roster, for a ring that has one.
    fn ring(&self) -> Result<Ring, MostroError> {
        let text = self
            .ring
            .as_deref()
            .ok_or_else(|| broken("a ring past its slots has no roster"))?;
        Ring::parse(text).map_err(|_| broken("a stored roster does not parse"))
    }
}

/// A member row.
struct Member {
    identity: String,
    trade_pubkey: String,
    node: String,
    commit_sig: Option<String>,
    edge_txid: Option<String>,
    edge_index: Option<i64>,
    edge_verified: bool,
}

impl Member {
    /// The outpoint of the channel this member says it opened, as `txid:index`.
    fn reported(&self) -> Option<String> {
        Some(format!("{}:{}", self.edge_txid.as_ref()?, self.edge_index?))
    }
}

async fn offer_by_id(pool: &SqlitePool, id: Uuid) -> Result<Option<Offer>, MostroError> {
    let row = sqlx::query(
        "SELECT creator_identity, offer, status, ring, window_ends_at \
         FROM ring_offers WHERE id = ?",
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
        creator_identity: row.try_get("creator_identity").map_err(db_err)?,
        offer,
        status: row.try_get("status").map_err(db_err)?,
        ring: row.try_get("ring").map_err(db_err)?,
        window_ends_at: row.try_get("window_ends_at").map_err(db_err)?,
    }))
}

/// A ring's members: in opening order once the roster is fixed, in joining order before.
async fn members_of(pool: &SqlitePool, id: Uuid) -> Result<Vec<Member>, MostroError> {
    let rows = sqlx::query(
        "SELECT identity, trade_pubkey, node, commit_sig, edge_txid, edge_index, edge_verified \
         FROM ring_members WHERE ring_offer_id = ? ORDER BY position, joined_at, identity",
    )
    .bind(id.to_string())
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let mut members = Vec::with_capacity(rows.len());
    for row in rows {
        let verified: i64 = row.try_get("edge_verified").map_err(db_err)?;
        members.push(Member {
            identity: row.try_get("identity").map_err(db_err)?,
            trade_pubkey: row.try_get("trade_pubkey").map_err(db_err)?,
            node: row.try_get("node").map_err(db_err)?,
            commit_sig: row.try_get("commit_sig").map_err(db_err)?,
            edge_txid: row.try_get("edge_txid").map_err(db_err)?,
            edge_index: row.try_get("edge_index").map_err(db_err)?,
            edge_verified: verified != 0,
        });
    }
    Ok(members)
}

/// Moves a ring from one of `from` to `to`; false when it was in none of them.
async fn advance(
    pool: &SqlitePool,
    id: Uuid,
    from: &[&str],
    to: &str,
) -> Result<bool, MostroError> {
    for state in from {
        let done = sqlx::query("UPDATE ring_offers SET status = ? WHERE id = ? AND status = ?")
            .bind(to)
            .bind(id.to_string())
            .bind(*state)
            .execute(pool)
            .await
            .map_err(db_err)?;
        if done.rows_affected() == 1 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ring_payload(msg: &Message) -> Result<&RingPayload, MostroError> {
    match msg.get_inner_message_kind().get_payload() {
        Some(Payload::Ring(payload)) => Ok(payload),
        _ => Err(refuse(CantDoReason::InvalidPayload)),
    }
}

fn order_id(msg: &Message) -> Result<Uuid, MostroError> {
    msg.get_inner_message_kind()
        .id
        .ok_or(refuse(CantDoReason::InvalidParameters))
}

/// Sends one ring message to a member's trade key.
async fn tell(
    to: &str,
    request_id: Option<u64>,
    id: Uuid,
    action: Action,
    payload: Option<RingPayload>,
) -> Result<(), MostroError> {
    enqueue_order_msg(
        request_id,
        Some(id),
        action,
        payload.map(Payload::Ring),
        stored_key(to)?,
        None,
    )
    .await;
    Ok(())
}

/// True when the message's id is a ring's. Used to keep a `cancel` for a ring away from the
/// escrow cancel path. A database error counts as "not a ring": the escrow path then answers
/// as it would for any unknown order.
pub async fn names_a_ring(ctx: &AppContext, msg: &Message) -> bool {
    let Some(id) = msg.get_inner_message_kind().id else {
        return false;
    };
    matches!(offer_by_id(ctx.pool(), id).await, Ok(Some(_)))
}

/// Routes one ring action.
pub async fn ring_action(
    ctx: &AppContext,
    action: &Action,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    match action {
        Action::RingOffer => ring_offer_action(ctx, msg, event).await,
        Action::TakeRingSlot => take_ring_slot_action(ctx, msg, event).await,
        Action::RingCommit => ring_commit_action(ctx, msg, event).await,
        Action::RingEdgeOpened => ring_edge_opened_action(ctx, msg, event).await,
        Action::RingEdgeVerified => ring_edge_verified_action(ctx, msg, event).await,
        Action::RingBondClaim => ring_bond_claim_action(ctx, msg, event).await,
        // The roster, the collected commits, the bond invoices and the closing report are the
        // instance's own to send. One that arrives here is refused unread.
        _ => Err(refuse(CantDoReason::InvalidAction)),
    }
}

/// A creator proposes a ring and takes its first slot. Checked: the terms, the lifetime, and
/// that the creator's node binds the identity key the transport proved.
async fn ring_offer_action(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    if ctx.maintenance().is_enabled() {
        return Err(refuse(CantDoReason::MaintenanceMode));
    }
    let kind = msg.get_inner_message_kind();
    let RingPayload::Offer(offer) = ring_payload(&msg)? else {
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
    // A bond is money this instance would hold: only if its operator turned bonds on, and only
    // up to the operator's limit.
    if !liquidity_bond::allowed(&liquidity_bond::settings(), offer.bond_sat) {
        return Err(refuse(CantDoReason::OutOfRangeSatsAmount));
    }
    let creator = event.identity.to_hex();
    offer
        .check_binding(&creator, now)
        .map_err(|_| refuse(CantDoReason::NotAuthorized))?;
    // The creator takes the first seat, so it meets the ring's own rules too.
    let candidate = Candidate {
        node: offer
            .seat
            .node_key()
            .map_err(|_| refuse(CantDoReason::InvalidParameters))?,
        network: offer.network,
        identity: &creator,
        binding: &offer.seat.binding,
        rules: offer.rules,
        must_be_in_graph: false,
    };
    liquidity_vet::vet(&candidate, now).await.map_err(refuse)?;

    let open: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM ring_offers \
         WHERE creator_identity = ? AND status = ? AND expires_at > ?",
    )
    .bind(&creator)
    .bind(PENDING)
    .bind(now as i64)
    .fetch_one(pool)
    .await
    .map_err(db_err)?
    .try_get("n")
    .map_err(db_err)?;
    if open >= MAX_OPEN_RINGS_PER_CREATOR {
        return Err(refuse(CantDoReason::TooManyRequests));
    }

    let id = Uuid::new_v4();
    let json = serde_json::to_string(offer)
        .map_err(|_| MostroInternalErr(ServiceError::MessageSerializationError))?;
    let seat = serde_json::to_string(&offer.seat)
        .map_err(|_| MostroInternalErr(ServiceError::MessageSerializationError))?;
    // The ring and its creator's seat land together or not at all.
    let mut tx = pool.begin().await.map_err(db_err)?;
    sqlx::query(
        "INSERT INTO ring_offers \
         (id, creator_identity, network, offer, slots, taken, status, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(&creator)
    .bind(offer.network.as_str())
    .bind(json)
    .bind(i64::from(offer.slots))
    .bind(PENDING)
    .bind(now as i64)
    .bind(offer.expires_at as i64)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO ring_members \
         (ring_offer_id, identity, trade_pubkey, node, seat, joined_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(&creator)
    .bind(event.sender.to_hex())
    .bind(&offer.seat.node)
    .bind(seat)
    .bind(now as i64)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    enqueue_order_msg(
        kind.request_id,
        Some(id),
        Action::RingOffer,
        Some(Payload::Ring(RingPayload::Offer(offer.clone()))),
        event.sender,
        None,
    )
    .await;
    sync_order_event(ctx, id).await;
    Ok(())
}

/// What the rows of a ring that just filled turn into.
struct Filled {
    roster: RingRoster,
    /// Trade keys of the members, in opening order.
    trade_keys: Vec<String>,
}

/// Fixes the roster of a ring whose last slot was just taken, inside the transaction that took
/// it: draws the order at random, writes each member's position, the roster and the window.
async fn fix_roster(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    offer: &RingOffer,
    now: u64,
) -> Result<Filled, MostroError> {
    let rows = sqlx::query(
        "SELECT identity, trade_pubkey, seat FROM ring_members WHERE ring_offer_id = ?",
    )
    .bind(id.to_string())
    .fetch_all(&mut **tx)
    .await
    .map_err(db_err)?;
    let mut drawn = Vec::with_capacity(rows.len());
    for row in rows {
        let identity: String = row.try_get("identity").map_err(db_err)?;
        let trade: String = row.try_get("trade_pubkey").map_err(db_err)?;
        let seat: String = row.try_get("seat").map_err(db_err)?;
        let seat: RingSeat = serde_json::from_str(&seat)
            .map_err(|_| MostroInternalErr(ServiceError::MessageSerializationError))?;
        drawn.push((identity, trade, seat));
    }
    // The generator is dropped before the next await: it must not cross one.
    {
        let mut rng = rand::thread_rng();
        drawn.shuffle(&mut rng);
    }
    let seats = drawn.iter().map(|(_, _, seat)| seat.clone()).collect();
    let roster = RingRoster::from_seats(offer.terms(), seats, now)
        .map_err(|_| broken("the members of a filled ring do not make a roster"))?;
    let ring = roster
        .validate()
        .map_err(|_| broken("a roster just built does not validate"))?;

    for (position, (identity, _, _)) in drawn.iter().enumerate() {
        sqlx::query(
            "UPDATE ring_members SET position = ? WHERE ring_offer_id = ? AND identity = ?",
        )
        .bind(position as i64)
        .bind(id.to_string())
        .bind(identity)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    }
    let moved = sqlx::query(
        "UPDATE ring_offers SET status = ?, ring = ?, ring_id = ?, window_ends_at = ? \
         WHERE id = ? AND status = ?",
    )
    .bind(COMMITTING)
    .bind(&roster.ring)
    .bind(ring.id())
    .bind(ring.window_ends_at() as i64)
    .bind(id.to_string())
    .bind(PENDING)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    if moved.rows_affected() != 1 {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    Ok(Filled {
        roster,
        trade_keys: drawn.into_iter().map(|(_, trade, _)| trade).collect(),
    })
}

/// A node runner takes a slot. Checked: the ring has a free slot and has not expired; the seat's
/// node binds the identity the transport proved, on the ring's network; neither that identity
/// nor that node is in the ring already. With the last slot the roster is fixed and sent to
/// every member.
async fn take_ring_slot_action(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    if ctx.maintenance().is_enabled() {
        return Err(refuse(CantDoReason::MaintenanceMode));
    }
    let id = order_id(&msg)?;
    let RingPayload::Take(seat) = ring_payload(&msg)? else {
        return Err(refuse(CantDoReason::InvalidPayload));
    };
    seat.validate()
        .map_err(|_| refuse(CantDoReason::InvalidParameters))?;
    let row = offer_by_id(pool, id)
        .await?
        .ok_or(refuse(CantDoReason::NotFound))?;
    let now = now();
    if row.status != PENDING || row.offer.is_expired(now) {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    let taker = event.identity.to_hex();
    seat.check_binding(row.offer.network, &taker, now)
        .map_err(|_| refuse(CantDoReason::NotAuthorized))?;
    // The member's node meets the ring's rules in this instance's graph and has not revoked its
    // binding.
    let candidate = Candidate {
        node: seat
            .node_key()
            .map_err(|_| refuse(CantDoReason::InvalidParameters))?,
        network: row.offer.network,
        identity: &taker,
        binding: &seat.binding,
        rules: row.offer.rules,
        must_be_in_graph: false,
    };
    liquidity_vet::vet(&candidate, now).await.map_err(refuse)?;
    let seat_json = serde_json::to_string(seat)
        .map_err(|_| MostroInternalErr(ServiceError::MessageSerializationError))?;

    let mut tx = pool.begin().await.map_err(db_err)?;
    // One statement decides whether there is a slot: two takers cannot both get the last one.
    let taken = sqlx::query(
        "UPDATE ring_offers SET taken = taken + 1 WHERE id = ? AND status = ? AND taken < slots",
    )
    .bind(id.to_string())
    .bind(PENDING)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    if taken.rows_affected() != 1 {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    let inserted = sqlx::query(
        "INSERT INTO ring_members \
         (ring_offer_id, identity, trade_pubkey, node, seat, joined_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(&taker)
    .bind(event.sender.to_hex())
    .bind(&seat.node)
    .bind(seat_json)
    .bind(now as i64)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        // This identity or this node is in the ring already: dropping the transaction gives
        // the slot back.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(refuse(CantDoReason::InvalidParameters));
        }
        Err(e) => return Err(db_err(e)),
    }
    let counts = sqlx::query("SELECT taken, slots FROM ring_offers WHERE id = ?")
        .bind(id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
    let taken: i64 = counts.try_get("taken").map_err(db_err)?;
    let slots: i64 = counts.try_get("slots").map_err(db_err)?;
    let filled = if taken == slots {
        Some(fix_roster(&mut tx, id, &row.offer, now).await?)
    } else {
        None
    };
    tx.commit().await.map_err(db_err)?;

    enqueue_order_msg(
        msg.get_inner_message_kind().request_id,
        Some(id),
        Action::TakeRingSlot,
        Some(Payload::Ring(RingPayload::Take(seat.clone()))),
        event.sender,
        None,
    )
    .await;
    if let Some(filled) = filled {
        for trade in &filled.trade_keys {
            let roster = RingPayload::Roster(filled.roster.clone());
            tell(trade, None, id, Action::RingRoster, Some(roster)).await?;
        }
    }
    sync_order_event(ctx, id).await;
    Ok(())
}

/// A member signs the ring id. Checked: the ring is collecting commits, the sender is a member,
/// and the signature is that member's over this ring's id. With the last commit all of them go
/// to every member, and the ring is open.
async fn ring_commit_action(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    let id = order_id(&msg)?;
    let RingPayload::Commit(commit) = ring_payload(&msg)? else {
        return Err(refuse(CantDoReason::InvalidPayload));
    };
    commit
        .validate()
        .map_err(|_| refuse(CantDoReason::InvalidParameters))?;
    let row = offer_by_id(pool, id)
        .await?
        .ok_or(refuse(CantDoReason::NotFound))?;
    if row.status != COMMITTING {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    let ring = row.ring()?;
    let sender = event.identity.to_hex();
    let members = members_of(pool, id).await?;
    if !members.iter().any(|m| m.identity == sender) {
        return Err(refuse(CantDoReason::IsNotYourOrder));
    }
    commit.verify(&ring, &event.identity).map_err(|e| match e {
        RingMessageError::Commit(_) => refuse(CantDoReason::InvalidSignature),
        _ => refuse(CantDoReason::InvalidParameters),
    })?;

    let stored = sqlx::query(
        "UPDATE ring_members SET commit_sig = ? \
         WHERE ring_offer_id = ? AND identity = ? AND commit_sig IS NULL",
    )
    .bind(&commit.signature)
    .bind(id.to_string())
    .bind(&sender)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if stored.rows_affected() != 1 {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }

    let members = members_of(pool, id).await?;
    if members.iter().any(|member| member.commit_sig.is_none()) {
        return Ok(());
    }
    if ring.terms.bond_sat > 0 {
        // Bonds first: nobody is told to open until every member's bond is locked.
        if advance(pool, id, &[COMMITTING], BONDING).await? {
            bonding_step_now(pool, id).await;
        }
        return Ok(());
    }
    // Only the handler that moves the ring to `open` sends the commits out.
    if !advance(pool, id, &[COMMITTING], OPEN).await? {
        return Ok(());
    }
    send_open(id, &ring, &members).await
}

/// Sends every member's commit to every member: the signal to open.
async fn send_open(id: Uuid, ring: &Ring, members: &[Member]) -> Result<(), MostroError> {
    let mut commits = Vec::with_capacity(members.len());
    for member in members {
        let signature = member
            .commit_sig
            .clone()
            .ok_or_else(|| broken("a ring opens without a commit"))?;
        commits.push(RingCommitment {
            nostr_pubkey: member.identity.clone(),
            signature,
        });
    }
    let open = RingOpen {
        ring_id: ring.id(),
        commits,
    };
    for member in members {
        let payload = RingPayload::Open(open.clone());
        tell(
            &member.trade_pubkey,
            None,
            id,
            Action::RingOpen,
            Some(payload),
        )
        .await?;
    }
    Ok(())
}

/// One bonding step now, on this instance's node. Best effort: a failure is logged and the
/// housekeeping job tries again, and it never fails the commit that led here.
async fn bonding_step_now(pool: &SqlitePool, id: Uuid) {
    let step = match liquidity_bond::node().await {
        Ok(node) => bonding_step(pool, &*node, id, now()).await,
        Err(e) => Err(e),
    };
    if let Err(e) = step {
        tracing::warn!("ring {id}: bonds not brought forward ({e}); housekeeping retries");
    }
}

/// Brings a ring that is collecting bonds forward at `now`:
///
/// 1. every member that has none yet gets a bond invoice, while there is still time to pay;
/// 2. the node is asked which bonds are locked;
/// 3. with all of them locked, the channels the graph already shows between each member and the
///    next are written down (they will not count as the opening), and the ring opens;
/// 4. if the time to pay is over, or the node let a bond go, the ring is canceled and the bonds
///    already locked go back. The time to pay is an hour, and never past the ring's window.
async fn bonding_step(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    id: Uuid,
    now: u64,
) -> Result<(), MostroError> {
    let Some(row) = offer_by_id(pool, id).await? else {
        return Ok(());
    };
    if row.status != BONDING {
        return Ok(());
    }
    let ring = row.ring()?;
    let ring_id = ring.id();
    let members = members_of(pool, id).await?;
    let window_end = u64::try_from(row.window_ends_at.unwrap_or(0)).unwrap_or(0);

    let had = liquidity_bond::of_order(pool, RING, id).await?;
    let started = had
        .iter()
        .map(|bond| u64::try_from(bond.created_at).unwrap_or(0))
        .min()
        .unwrap_or(now);
    let pay_by = started.saturating_add(BOND_PAY_WINDOW_SECS).min(window_end);
    if now < pay_by {
        let description = format!("bipnip ring bond {}", &ring_id[..16]);
        for member in &members {
            if had
                .iter()
                .any(|bond| bond.payer_identity == member.identity)
            {
                continue;
            }
            let request = liquidity_bond::Request {
                kind: RING,
                order_id: id,
                payer_identity: &member.identity,
                payer_trade_pubkey: &member.trade_pubkey,
                amount_sat: ring.terms.bond_sat,
                cltv_delta: bond_cltv_delta(window_end.saturating_sub(now)),
                description: &description,
            };
            let invoice = liquidity_bond::request(pool, node, &request, now).await?;
            let payload = RingPayload::Invoice(RingInvoice {
                ring_id: ring_id.clone(),
                invoice,
            });
            tell(
                &member.trade_pubkey,
                None,
                id,
                Action::RingBondInvoice,
                Some(payload),
            )
            .await?;
        }
    }

    let bonds = liquidity_bond::refresh(pool, node, RING, id).await?;
    let all_locked = bonds.len() == members.len()
        && bonds
            .iter()
            .all(|bond| bond.state == liquidity_bond::LOCKED);
    // Only while there is still a window to open in: a ring whose bonds lock after its window
    // (the node could not be asked for that long) is canceled below, and the bonds go back.
    if all_locked && now < window_end {
        for (place, member) in members.iter().enumerate() {
            let next = &members[(place + 1) % members.len()];
            let before = liquidity_bond::channels_between(
                node,
                &member.node,
                &next.node,
                ring.terms.capacity_sat,
            )
            .await?;
            let bond = bonds
                .iter()
                .find(|bond| bond.payer_identity == member.identity)
                .ok_or_else(|| broken("a member of a bonded ring has no bond"))?;
            liquidity_bond::note_graph_before(pool, bond.id, &before).await?;
        }
        if advance(pool, id, &[BONDING], OPEN).await? {
            send_open(id, &ring, &members).await?;
        }
        return Ok(());
    }

    let gone = bonds.iter().any(|bond| {
        bond.state != liquidity_bond::REQUESTED && bond.state != liquidity_bond::LOCKED
    });
    if (now >= pay_by || gone) && advance(pool, id, &[BONDING], CANCELED).await? {
        liquidity_bond::release_all(pool, node, RING, id).await?;
        for member in &members {
            tell(&member.trade_pubkey, None, id, Action::Canceled, None).await?;
        }
    }
    Ok(())
}

/// Decides every bond of a ring whose window has ended, one member at a time. A member's bond
/// goes back when the member it opened to confirmed the channel, or when this instance's node
/// sees the channel in the graph: between the member's node and the next member's, of the
/// ring's capacity, not there before the ring opened, not a channel another member reported,
/// and, if the member reported one, that very channel. Otherwise the bond is taken and owed to
/// the next member. An error (the node cannot be asked) leaves the remaining bonds undecided.
async fn judge(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    id: Uuid,
    now: u64,
) -> Result<(), MostroError> {
    let Some(row) = offer_by_id(pool, id).await? else {
        return Ok(());
    };
    let ring = row.ring()?;
    let members = members_of(pool, id).await?;
    let bonds = liquidity_bond::of_order(pool, RING, id).await?;
    let reported: Vec<Option<String>> = members.iter().map(Member::reported).collect();
    for (place, member) in members.iter().enumerate() {
        let Some(bond) = bonds
            .iter()
            .find(|bond| bond.payer_identity == member.identity)
        else {
            continue;
        };
        if bond.state != liquidity_bond::LOCKED {
            continue;
        }
        let next = &members[(place + 1) % members.len()];
        let mut kept = member.edge_verified;
        if !kept {
            let in_graph = liquidity_bond::channels_between(
                node,
                &member.node,
                &next.node,
                ring.terms.capacity_sat,
            )
            .await?;
            let counts = |outpoint: &String| {
                let was_there = bond.graph_before.contains(outpoint);
                let someone_elses = reported
                    .iter()
                    .enumerate()
                    .any(|(other, theirs)| other != place && theirs.as_ref() == Some(outpoint));
                !was_there && !someone_elses
            };
            kept = match &reported[place] {
                Some(own) => in_graph
                    .iter()
                    .any(|outpoint| outpoint == own && counts(outpoint)),
                None => in_graph.iter().any(counts),
            };
        }
        if kept {
            liquidity_bond::release(pool, node, bond.id).await?;
        } else {
            liquidity_bond::slash(pool, node, bond.id, &next.identity, &next.trade_pubkey, now)
                .await?;
        }
    }
    Ok(())
}

/// Lets go every bond of a ring that is still held, now. Best effort: a bond the node could not
/// be told about is picked up by the housekeeping job.
async fn release_bonds_now(pool: &SqlitePool, id: Uuid) {
    let released = async {
        if liquidity_bond::of_order(pool, RING, id).await?.is_empty() {
            return Ok(());
        }
        let node = liquidity_bond::node().await?;
        liquidity_bond::release_all(pool, &*node, RING, id).await
    };
    if let Err::<(), MostroError>(e) = released.await {
        tracing::warn!("ring {id}: bonds not released ({e}); housekeeping retries");
    }
}

/// A member that is owed a bond sends its invoice for it. Checked here: the ring ended with its
/// window (`partial`) and the claim names it. Checked by [`liquidity_bond::claim`]: the sender is
/// the member the taken bond is owed to, and the invoice asks for exactly what is owed.
async fn ring_bond_claim_action(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    let id = order_id(&msg)?;
    let RingPayload::Invoice(claim) = ring_payload(&msg)? else {
        return Err(refuse(CantDoReason::InvalidPayload));
    };
    claim
        .validate()
        .map_err(|_| refuse(CantDoReason::InvalidParameters))?;
    let row = offer_by_id(pool, id)
        .await?
        .ok_or(refuse(CantDoReason::NotFound))?;
    if row.status != PARTIAL {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    if claim.ring_id != row.ring()?.id() {
        return Err(refuse(CantDoReason::InvalidParameters));
    }
    let sender = event.identity.to_hex();
    liquidity_bond::claim(pool, RING, id, &sender, &claim.invoice, now()).await
}

/// The ring, its members and the sender's place among them, for a ring that is open and whose
/// window has not ended.
async fn open_ring(
    pool: &SqlitePool,
    id: Uuid,
    event: &UnwrappedMessage,
) -> Result<(Ring, Vec<Member>, usize), MostroError> {
    let row = offer_by_id(pool, id)
        .await?
        .ok_or(refuse(CantDoReason::NotFound))?;
    let window_over = row.window_ends_at.is_none_or(|end| now() as i64 >= end);
    if row.status != OPEN || window_over {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    let ring = row.ring()?;
    let members = members_of(pool, id).await?;
    let sender = event.identity.to_hex();
    let place = members
        .iter()
        .position(|m| m.identity == sender)
        .ok_or(refuse(CantDoReason::IsNotYourOrder))?;
    Ok((ring, members, place))
}

/// A member reports the channel it opened to the next member. Recorded once, as a claim, and
/// passed on to that member, whose node is the judge of it.
async fn ring_edge_opened_action(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    let id = order_id(&msg)?;
    let payload = ring_payload(&msg)?;
    let RingPayload::Edge(edge) = payload else {
        return Err(refuse(CantDoReason::InvalidPayload));
    };
    edge.validate()
        .map_err(|_| refuse(CantDoReason::InvalidParameters))?;
    let (ring, members, place) = open_ring(pool, id, event).await?;
    if edge.ring_id != ring.id() {
        return Err(refuse(CantDoReason::InvalidParameters));
    }
    // One channel is one member's opening: an outpoint another member reported is refused.
    let outpoint = format!("{}:{}", edge.funding_txid, edge.output_index);
    let someone_elses = members
        .iter()
        .enumerate()
        .any(|(other, member)| other != place && member.reported().as_ref() == Some(&outpoint));
    if someone_elses {
        return Err(refuse(CantDoReason::InvalidParameters));
    }
    let recorded = sqlx::query(
        "UPDATE ring_members SET edge_txid = ?, edge_index = ? \
         WHERE ring_offer_id = ? AND identity = ? AND edge_txid IS NULL",
    )
    .bind(&edge.funding_txid)
    .bind(i64::from(edge.output_index))
    .bind(id.to_string())
    .bind(&members[place].identity)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if recorded.rows_affected() != 1 {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    let next = &members[(place + 1) % members.len()];
    tell(
        &next.trade_pubkey,
        None,
        id,
        Action::RingEdgeOpened,
        Some(payload.clone()),
    )
    .await
}

/// A member confirms the channel the previous member opened to it. Checked: it names the very
/// outpoint that member reported. The opener is told; when every channel is confirmed the ring
/// closes as a success.
async fn ring_edge_verified_action(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    let id = order_id(&msg)?;
    let payload = ring_payload(&msg)?;
    let RingPayload::Edge(edge) = payload else {
        return Err(refuse(CantDoReason::InvalidPayload));
    };
    edge.validate()
        .map_err(|_| refuse(CantDoReason::InvalidParameters))?;
    let (ring, members, place) = open_ring(pool, id, event).await?;
    if edge.ring_id != ring.id() {
        return Err(refuse(CantDoReason::InvalidParameters));
    }
    let n = members.len();
    let opener = &members[(place + n - 1) % n];
    let reported = opener.edge_txid.as_deref() == Some(edge.funding_txid.as_str())
        && opener.edge_index == Some(i64::from(edge.output_index));
    if !reported {
        return Err(refuse(CantDoReason::InvalidParameters));
    }
    let confirmed = sqlx::query(
        "UPDATE ring_members SET edge_verified = 1 \
         WHERE ring_offer_id = ? AND identity = ? AND edge_verified = 0",
    )
    .bind(id.to_string())
    .bind(&opener.identity)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if confirmed.rows_affected() != 1 {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    tell(
        &opener.trade_pubkey,
        None,
        id,
        Action::RingEdgeVerified,
        Some(payload.clone()),
    )
    .await?;

    let all = members_of(pool, id).await?.iter().all(|m| m.edge_verified);
    if all {
        close(pool, id, SUCCESS).await?;
        // Every channel is there: every bond goes back.
        release_bonds_now(pool, id).await;
        sync_order_event(ctx, id).await;
    }
    Ok(())
}

/// Ends a ring that has a roster as `to` (`success` or `partial`) and tells every member which
/// channels were confirmed and whose bond was taken. Does nothing if the ring was already over.
/// The bonds themselves are decided before this is called ([`judge`]); this only reports them.
async fn close(pool: &SqlitePool, id: Uuid, to: &str) -> Result<bool, MostroError> {
    if !advance(pool, id, &[OPEN, COMMITTING], to).await? {
        return Ok(false);
    }
    let row = offer_by_id(pool, id)
        .await?
        .ok_or_else(|| broken("a ring vanished while closing"))?;
    let members = members_of(pool, id).await?;
    let verified = members
        .iter()
        .enumerate()
        .filter(|(_, m)| m.edge_verified)
        .map(|(position, _)| position as u8)
        .collect();
    let bonds = liquidity_bond::of_order(pool, RING, id).await?;
    let slashed = members
        .iter()
        .enumerate()
        .filter(|(_, member)| {
            bonds
                .iter()
                .any(|bond| bond.payer_identity == member.identity && bond.was_taken())
        })
        .map(|(position, _)| position as u8)
        .collect();
    let ring = row.ring()?;
    // This instance's account of each edge, for announced rings: opened when the receiver
    // confirmed it or the bond came back, missing otherwise.
    if ring.terms.announce {
        let now = now();
        for (place, member) in members.iter().enumerate() {
            let next = &members[(place + 1) % members.len()];
            let bond = bonds
                .iter()
                .find(|bond| bond.payer_identity == member.identity);
            let opened = member.edge_verified || bond.is_some_and(|bond| !bond.was_taken());
            let decided = liquidity_outcome::Decided {
                deal: Deal::Ring,
                subject: ring.id(),
                network: ring.terms.network,
                nodes: [member.node.clone(), next.node.clone()],
                result: if opened {
                    OutcomeResult::Opened
                } else {
                    OutcomeResult::Missing
                },
                outpoint: member.reported().filter(|_| member.edge_verified),
            };
            if let Err(e) = liquidity_outcome::queue(pool, &decided, now).await {
                tracing::warn!("ring {id}: outcome not kept: {e}");
            }
        }
    }
    let closed = RingClosed {
        ring_id: ring.id(),
        verified,
        slashed,
    };
    for member in &members {
        let payload = RingPayload::Closed(closed.clone());
        tell(
            &member.trade_pubkey,
            None,
            id,
            Action::RingClosed,
            Some(payload),
        )
        .await?;
    }
    Ok(true)
}

/// A cancel while slots are still open. The creator withdraws the ring, and every member is
/// told; any other member gives its slot back. Once the roster is fixed nobody can cancel: a
/// ring then ends by its channels or by its window.
pub async fn ring_cancel_action(
    ctx: &AppContext,
    msg: Message,
    event: &UnwrappedMessage,
) -> Result<(), MostroError> {
    let pool = ctx.pool();
    let id = order_id(&msg)?;
    let request_id = msg.get_inner_message_kind().request_id;
    let row = offer_by_id(pool, id)
        .await?
        .ok_or(refuse(CantDoReason::NotFound))?;
    let sender = event.identity.to_hex();
    let members = members_of(pool, id).await?;
    if !members.iter().any(|m| m.identity == sender) {
        return Err(refuse(CantDoReason::IsNotYourOrder));
    }
    if row.status == CANCELED {
        return Err(refuse(CantDoReason::OrderAlreadyCanceled));
    }
    if row.status != PENDING {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }

    if sender == row.creator_identity {
        if !advance(pool, id, &[PENDING], CANCELED).await? {
            return Err(refuse(CantDoReason::NotAllowedByStatus));
        }
        for member in &members {
            let request_id = (member.identity == sender).then_some(request_id).flatten();
            tell(&member.trade_pubkey, request_id, id, Action::Canceled, None).await?;
        }
    } else {
        // The slot count and the member row change together or not at all.
        let mut tx = pool.begin().await.map_err(db_err)?;
        let freed = sqlx::query(
            "UPDATE ring_offers SET taken = taken - 1 WHERE id = ? AND status = ? AND taken > 1",
        )
        .bind(id.to_string())
        .bind(PENDING)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        if freed.rows_affected() != 1 {
            return Err(refuse(CantDoReason::NotAllowedByStatus));
        }
        sqlx::query("DELETE FROM ring_members WHERE ring_offer_id = ? AND identity = ?")
            .bind(id.to_string())
            .bind(&sender)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        enqueue_order_msg(
            request_id,
            Some(id),
            Action::Canceled,
            None,
            event.sender,
            None,
        )
        .await;
    }
    sync_order_event(ctx, id).await;
    Ok(())
}

/// The status the public order event shows for an internal one.
fn public_status(status: &str) -> Option<RingOrderStatus> {
    Some(match status {
        PENDING => RingOrderStatus::Pending,
        COMMITTING | BONDING | OPEN => RingOrderStatus::InProgress,
        SUCCESS => RingOrderStatus::Success,
        PARTIAL => RingOrderStatus::Partial,
        CANCELED => RingOrderStatus::Canceled,
        EXPIRED => RingOrderStatus::Expired,
        _ => return None,
    })
}

/// What the order event shows: the public status and the slots taken.
fn shown(status: &str, taken: i64) -> Option<(RingOrderStatus, u8)> {
    Some((public_status(status)?, u8::try_from(taken).ok()?))
}

/// What one attempt to bring a ring's order event up to date did.
#[derive(Debug, PartialEq, Eq)]
enum OrderSync {
    /// The event was already up to date.
    Current,
    /// A new event went out.
    Published,
    /// Nothing needed publishing; the row is marked up to date.
    Skipped,
}

/// Brings the public order event of ring `id` up to date with its status and slot count,
/// sending through `send`. Nothing is sent when what the event shows did not change
/// (`committing` to `open`, say), when the offer's expiry has passed (the event carries it as
/// NIP-40 expiration, so relays have dropped it and would refuse a new one), or when relays
/// never saw the order and it is already over. A failed `send` leaves the row behind, and the
/// housekeeping job tries again.
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
        "SELECT offer, status, taken, synced, order_event_at FROM ring_offers WHERE id = ?",
    )
    .bind(id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let Some(row) = row else {
        return Ok(OrderSync::Current);
    };
    let status: String = row.try_get("status").map_err(db_err)?;
    let taken: i64 = row.try_get("taken").map_err(db_err)?;
    let synced: Option<String> = row.try_get("synced").map_err(db_err)?;
    let mark = format!("{status}:{taken}");
    if synced.as_deref() == Some(mark.as_str()) {
        return Ok(OrderSync::Current);
    }
    let (public, slots_taken) =
        shown(&status, taken).ok_or_else(|| broken("a ring has an unknown status"))?;
    let json: String = row.try_get("offer").map_err(db_err)?;
    let offer: RingOffer = serde_json::from_str(&json)
        .map_err(|_| MostroInternalErr(ServiceError::MessageSerializationError))?;
    let last_at: Option<i64> = row.try_get("order_event_at").map_err(db_err)?;

    // What relays show now, if anything.
    let before = synced.as_deref().and_then(|mark| {
        let (status, taken) = mark.split_once(':')?;
        shown(status, taken.parse().ok()?)
    });
    let over = matches!(public, RingOrderStatus::Canceled | RingOrderStatus::Expired);
    let nothing_to_send = before == Some((public, slots_taken))
        || offer.is_expired(now)
        || (before.is_none() && over);
    let (outcome, event_at) = if nothing_to_send {
        (OrderSync::Skipped, last_at)
    } else {
        // Always newer than the last one, so a relay replaces it even within the same second.
        let newer_than_last =
            last_at.map_or(0, |t| u64::try_from(t).unwrap_or(0).saturating_add(1));
        let at = now.max(newer_than_last);
        let event = RingOrder::from_offer(id, public, slots_taken, &offer)
            .map_err(|_| MostroInternalErr(ServiceError::MessageSerializationError))?
            .to_event_builder()
            .custom_created_at(Timestamp::from(at))
            .finalize(keys)
            .map_err(|e| MostroInternalErr(ServiceError::NostrError(e.to_string())))?;
        send(event).await?;
        (OrderSync::Published, Some(at as i64))
    };
    sqlx::query("UPDATE ring_offers SET synced = ?, order_event_at = ? WHERE id = ?")
        .bind(&mark)
        .bind(event_at)
        .bind(id.to_string())
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(outcome)
}

/// Brings the order event of ring `id` up to date on this instance's relays. Best effort: a
/// failure is logged and left to the housekeeping job, and never fails the step that led here.
async fn sync_order_event(ctx: &AppContext, id: Uuid) {
    let client = ctx.nostr_client();
    let synced = sync_order_event_with(ctx.pool(), ctx.keys(), id, now(), |event| async move {
        crate::publish::send_event_first_ack(client, &event, |_| {}).await
    })
    .await;
    if let Err(e) = synced {
        tracing::warn!("ring order {id}: order event not published ({e}); housekeeping retries");
    }
}

async fn ids(
    pool: &SqlitePool,
    sql: &'static str,
    statuses: &[&str],
    at: i64,
) -> Result<Vec<Uuid>, MostroError> {
    let mut query = sqlx::query(sql);
    for status in statuses {
        query = query.bind(*status);
    }
    let rows = query.bind(at).fetch_all(pool).await.map_err(db_err)?;
    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id").map_err(db_err)?;
        if let Ok(id) = Uuid::parse_str(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// One housekeeping pass at `now`:
///
/// 1. rings whose slots did not fill before their expiry become `expired`, and the members that
///    had joined are told;
/// 2. rings whose window has ended are closed as `partial`, and every member is told which
///    channels were confirmed (the channels that were opened stand); a ring with bonds is left
///    to [`bond_pass`], which decides its bonds first;
/// 3. order events that are behind are brought up to date, stopping at the first failure.
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
    let unfilled = ids(
        pool,
        "SELECT id FROM ring_offers WHERE status = ? AND expires_at <= ?",
        &[PENDING],
        now as i64,
    )
    .await?;
    for id in unfilled {
        if advance(pool, id, &[PENDING], EXPIRED).await? {
            for member in members_of(pool, id).await? {
                tell(&member.trade_pubkey, None, id, Action::Canceled, None).await?;
            }
        }
    }

    let overdue = ids(
        pool,
        "SELECT id FROM ring_offers WHERE status IN (?, ?) AND window_ends_at <= ?",
        &[COMMITTING, OPEN],
        now as i64,
    )
    .await?;
    for id in overdue {
        if liquidity_bond::of_order(pool, RING, id).await?.is_empty() {
            close(pool, id, PARTIAL).await?;
        }
    }

    let rows = sqlx::query(
        "SELECT id FROM ring_offers WHERE synced IS NULL OR synced != status || ':' || taken \
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

/// The part of housekeeping that needs this instance's node, at `now`:
///
/// 1. rings collecting bonds are brought forward ([`bonding_step`]);
/// 2. rings with bonds whose window has ended have each bond decided ([`judge`]) and are then
///    closed; if the node cannot be asked, the ring stays open until it can;
/// 3. a bond still held on a ring that is over is let go (a safety net: it errs towards the
///    member that paid);
/// 4. node calls still owed and payouts are moved on (`liquidity_bond::housekeeping`).
async fn bond_pass(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    now: u64,
) -> Result<(), MostroError> {
    // `created_at <= now` is always true; it is there for the helper's last bind.
    let bonding = ids(
        pool,
        "SELECT id FROM ring_offers WHERE status = ? AND created_at <= ?",
        &[BONDING],
        now as i64,
    )
    .await?;
    for id in bonding {
        bonding_step(pool, node, id, now).await?;
    }

    let overdue = ids(
        pool,
        "SELECT id FROM ring_offers WHERE status = ? AND window_ends_at <= ?",
        &[OPEN],
        now as i64,
    )
    .await?;
    // The verdict reads this node's graph: not before the node says it is synced, or a channel
    // gossip has not brought yet would look missing. The ring stays open until then.
    // A node that cannot be asked at all fails the verdict below, as before.
    let lagging = matches!(node.node_info().await, Ok(info) if !info.synced);
    for id in overdue {
        if liquidity_bond::of_order(pool, RING, id).await?.is_empty() {
            continue;
        }
        if lagging {
            tracing::info!("ring {id}: its bonds wait until this node is synced");
            continue;
        }
        judge(pool, node, id, now).await?;
        close(pool, id, PARTIAL).await?;
    }

    let rows = sqlx::query(
        "SELECT b.id AS id FROM liquidity_bonds b JOIN ring_offers r ON r.id = b.order_id \
         WHERE b.kind = 'ring' AND b.state IN ('requested', 'locked') \
         AND r.status IN ('success', 'partial', 'canceled', 'expired')",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    for row in rows {
        let bond: String = row.try_get("id").map_err(db_err)?;
        if let Ok(bond) = Uuid::parse_str(&bond) {
            liquidity_bond::release(pool, node, bond).await?;
        }
    }

    liquidity_bond::housekeeping(pool, node, now).await
}

/// True when [`bond_pass`] has something to do, so an instance without bonds never connects to
/// its node for them.
async fn bond_work(pool: &SqlitePool) -> Result<bool, MostroError> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM ring_offers WHERE status = ?")
        .bind(BONDING)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    let bonding: i64 = row.try_get("n").map_err(db_err)?;
    Ok(bonding > 0
        || crate::app::lease::bonding_count(pool).await? > 0
        || liquidity_bond::any_open(pool).await?)
}

/// One pass over the bonds now, of rings and of leases, on this instance's node. Called by the
/// scheduler, more often than the full housekeeping pass: a ring opens, and a take goes to its
/// seller, as soon as the bond is seen locked.
pub async fn bond_pass_now(ctx: &AppContext) {
    let pool = ctx.pool();
    let pass = async {
        liquidity_bond::forfeit_unclaimed(pool, now()).await?;
        if !bond_work(pool).await? {
            return Ok(());
        }
        let node = liquidity_bond::node().await?;
        // Rings and leases are passed over separately: a problem with one does not hold up
        // the other.
        if let Err(e) = crate::app::lease::bond_pass(pool, &*node, now()).await {
            tracing::warn!("lease bonds: pass ended early ({e}); the next one continues");
        }
        bond_pass(pool, &*node, now()).await
    };
    if let Err::<(), MostroError>(e) = pass.await {
        tracing::warn!("ring bonds: pass ended early ({e}); the next one continues");
    }
}

/// One housekeeping pass now, on this instance's relays. Called by the scheduler.
pub async fn housekeeping_pass(ctx: &AppContext) {
    let client = ctx.nostr_client();
    let pass = housekeeping_pass_with(ctx.pool(), ctx.keys(), now(), |event| async move {
        crate::publish::send_event_first_ack(client, &event, |_| {}).await
    })
    .await;
    if let Err(e) = pass {
        tracing::warn!("ring housekeeping: pass ended early ({e}); the next one continues");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::context::test_utils::{test_settings, TestContextBuilder};
    use crate::app::liquidity_bond::testing::{self, MockNode};
    use bipnip_ln::HoldState;
    use mostro_core::bond::{payout_sat, routing_reserve_sat};
    use mostro_core::node_binding::{
        sign_ln_message, Action as BindingAction, Network, SignedStatement, Statement,
    };
    use mostro_core::ring_message::{RingCommit, RingEdge};
    use secp256k1::{Secp256k1, SecretKey};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;

    /// A node runner: an identity key, a trade key, and a node key the identity is bound to.
    struct Party {
        identity: Keys,
        trade: Keys,
        node: SecretKey,
        /// The bond this party asks for in a ring it creates.
        bond_sat: u64,
    }

    impl Party {
        fn new() -> Self {
            let node =
                SecretKey::from_slice(&Keys::generate().secret_key().to_secret_bytes()).unwrap();
            Party {
                identity: Keys::generate(),
                trade: Keys::generate(),
                node,
                bond_sat: 0,
            }
        }

        /// A party whose rings ask every member for a bond.
        fn bonded() -> Self {
            Party {
                bond_sat: BOND,
                ..Party::new()
            }
        }

        fn node_key(&self) -> secp256k1::PublicKey {
            secp256k1::PublicKey::from_secret_key(&Secp256k1::signing_only(), &self.node)
        }

        /// This node's binding of `identity`.
        fn binding_of(&self, identity: &Keys) -> String {
            let statement = Statement::new(
                BindingAction::Bind,
                Network::Regtest,
                &identity.public_key().to_hex(),
                self.node_key(),
                now() - 60,
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

        fn seat(&self) -> RingSeat {
            RingSeat {
                node: self.node_key().to_string(),
                binding: self.binding_of(&self.identity),
                node_address: Some("203.0.113.7:9735".into()),
            }
        }

        fn offer(&self, slots: u8) -> RingOffer {
            RingOffer {
                network: Network::Regtest,
                capacity_sat: 2_000_000,
                slots,
                announce: true,
                open_window_secs: 48 * 3_600,
                bond_sat: self.bond_sat,
                expires_at: now() + 86_400,
                seat: self.seat(),
                rules: Default::default(),
            }
        }

        /// Sends one ring action as this party and returns the handler's verdict.
        async fn send(
            &self,
            ctx: &AppContext,
            id: Option<Uuid>,
            action: Action,
            payload: Option<RingPayload>,
        ) -> Result<(), MostroError> {
            let msg = Message::new_order(
                id,
                Some(7),
                None,
                action.clone(),
                payload.map(Payload::Ring),
            );
            let event = UnwrappedMessage {
                message: msg.clone(),
                signature: None,
                sender: self.trade.public_key(),
                identity: self.identity.public_key(),
                created_at: Timestamp::now(),
            };
            if action == Action::Cancel {
                assert!(names_a_ring(ctx, &msg).await);
                return ring_cancel_action(ctx, msg, &event).await;
            }
            ring_action(ctx, &action, msg, &event).await
        }

        async fn take(&self, ctx: &AppContext, id: Uuid) -> Result<(), MostroError> {
            let seat = Some(RingPayload::Take(self.seat()));
            self.send(ctx, Some(id), Action::TakeRingSlot, seat).await
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

        /// The ring payloads this party was sent under `action`, oldest first.
        async fn got(&self, action: Action) -> Vec<RingPayload> {
            self.inbox()
                .await
                .into_iter()
                .filter(|kind| kind.action == action)
                .filter_map(|kind| match kind.payload {
                    Some(Payload::Ring(payload)) => Some(payload),
                    _ => None,
                })
                .collect()
        }

        async fn count(&self, action: Action) -> usize {
            self.inbox()
                .await
                .iter()
                .filter(|kind| kind.action == action)
                .count()
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

    async fn taken(ctx: &AppContext, id: Uuid) -> i64 {
        sqlx::query("SELECT taken FROM ring_offers WHERE id = ?")
            .bind(id.to_string())
            .fetch_one(ctx.pool())
            .await
            .unwrap()
            .get("taken")
    }

    /// The creator's ring is stored; returns its order id.
    #[tokio::test]
    async fn a_ring_with_rules_takes_only_nodes_that_meet_them_here() {
        let ctx = ctx().await;
        let (creator, member) = (Party::new(), Party::new());
        let rules = mostro_core::rules::Rules {
            min_channels: 1,
            ..Default::default()
        };
        let mut offer = creator.offer(2);
        offer.rules = rules;
        // The creator takes the first seat, so its node is held to the rules too.
        assert_eq!(
            refused(
                creator
                    .send(
                        &ctx,
                        None,
                        Action::RingOffer,
                        Some(RingPayload::Offer(offer.clone()))
                    )
                    .await
            ),
            CantDoReason::RulesNotMet
        );
        let graph = testing::shared();
        graph.know(&creator.node_key().to_string(), 1, 500_000);
        creator
            .send(
                &ctx,
                None,
                Action::RingOffer,
                Some(RingPayload::Offer(offer)),
            )
            .await
            .unwrap();
        let id = creator.inbox().await.pop().unwrap().id.unwrap();
        assert_eq!(
            refused(member.take(&ctx, id).await),
            CantDoReason::RulesNotMet
        );
        graph.know(&member.node_key().to_string(), 3, 3_000_000);
        member.take(&ctx, id).await.unwrap();
        assert_eq!(status(&ctx, id).await, COMMITTING);
        // The roster names the rules: every member's commit covers them.
        let rosters = member.got(Action::RingRoster).await;
        let RingPayload::Roster(roster) = &rosters[0] else {
            panic!("not a roster");
        };
        let (ring, _) = roster.check(now()).unwrap();
        assert_eq!(ring.terms.rules, rules);
    }

    async fn offered(ctx: &AppContext, creator: &Party, slots: u8) -> Uuid {
        let offer = Some(RingPayload::Offer(creator.offer(slots)));
        creator
            .send(ctx, None, Action::RingOffer, offer)
            .await
            .unwrap();
        let echo = creator.inbox().await.pop().unwrap();
        assert_eq!(echo.action, Action::RingOffer);
        assert_eq!(echo.request_id, Some(7));
        echo.id.unwrap()
    }

    /// A ring of all `parties`, full: the first creates it, the others take a slot. Returns the
    /// order id and the roster every member was sent.
    async fn filled(ctx: &AppContext, parties: &[Party]) -> (Uuid, Ring) {
        let id = offered(ctx, &parties[0], parties.len() as u8).await;
        for party in &parties[1..] {
            party.take(ctx, id).await.unwrap();
        }
        assert_eq!(status(ctx, id).await, COMMITTING);
        let mut rings = Vec::new();
        for party in parties {
            let rosters = party.got(Action::RingRoster).await;
            assert_eq!(rosters.len(), 1, "one roster each");
            let RingPayload::Roster(roster) = &rosters[0] else {
                panic!("not a roster");
            };
            // What a member checks on its own: every binding, and the offer's terms.
            let (ring, keys) = roster.check(now()).unwrap();
            assert_eq!(keys.len(), parties.len());
            parties[0]
                .offer(parties.len() as u8)
                .check_ring(&ring)
                .unwrap();
            rings.push(ring);
        }
        assert!(rings.windows(2).all(|pair| pair[0] == pair[1]), "one ring");
        (id, rings.remove(0))
    }

    /// The party whose node sits at `position` of `ring`.
    fn at<'a>(parties: &'a [Party], ring: &Ring, position: usize) -> &'a Party {
        let node = ring.members[position % ring.members.len()];
        parties
            .iter()
            .find(|party| party.node_key() == node)
            .expect("a member")
    }

    async fn commit(
        ctx: &AppContext,
        id: Uuid,
        party: &Party,
        ring: &Ring,
    ) -> Result<(), MostroError> {
        let commit = Some(RingPayload::Commit(RingCommit::sign(ring, &party.identity)));
        party.send(ctx, Some(id), Action::RingCommit, commit).await
    }

    /// A full ring with every commit in.
    async fn opened(ctx: &AppContext, parties: &[Party]) -> (Uuid, Ring) {
        let (id, ring) = filled(ctx, parties).await;
        for party in parties {
            commit(ctx, id, party, &ring).await.unwrap();
        }
        assert_eq!(status(ctx, id).await, OPEN);
        (id, ring)
    }

    fn edge(ring: &Ring, n: u8) -> RingPayload {
        RingPayload::Edge(RingEdge {
            ring_id: ring.id(),
            funding_txid: format!("{n:02x}").repeat(32),
            output_index: u32::from(n),
        })
    }

    #[tokio::test]
    async fn a_ring_of_three_runs_from_offer_to_success() {
        let ctx = ctx().await;
        let parties = [Party::new(), Party::new(), Party::new()];
        let (id, ring) = filled(&ctx, &parties).await;
        assert_eq!(taken(&ctx, id).await, 3);
        // Each taker was told its slot is taken.
        for party in &parties[1..] {
            assert_eq!(party.count(Action::TakeRingSlot).await, 1);
        }

        // Nobody is told the ring is open until the last commit is in.
        for (n, party) in parties.iter().enumerate() {
            for other in &parties {
                assert_eq!(other.count(Action::RingOpen).await, 0, "after {n} commits");
            }
            commit(&ctx, id, party, &ring).await.unwrap();
            // A repeat changes nothing.
            let again = commit(&ctx, id, party, &ring).await;
            assert_eq!(refused(again), CantDoReason::NotAllowedByStatus);
        }
        assert_eq!(status(&ctx, id).await, OPEN);
        let (_, keys) = match &parties[0].got(Action::RingRoster).await[0] {
            RingPayload::Roster(roster) => roster.check(now()).unwrap(),
            _ => panic!("not a roster"),
        };
        for party in &parties {
            let opens = party.got(Action::RingOpen).await;
            assert_eq!(opens.len(), 1);
            let RingPayload::Open(open) = &opens[0] else {
                panic!("not the commits");
            };
            // What a member checks before it opens: one valid commit per member.
            open.check(&ring, &keys).unwrap();
        }

        // Each member reports its channel; only the member it opened to is told. That member
        // confirms; only the opener is told.
        for position in 0..3 {
            let opener = at(&parties, &ring, position);
            let receiver = at(&parties, &ring, position + 1);
            let report = edge(&ring, position as u8 + 1);
            opener
                .send(&ctx, Some(id), Action::RingEdgeOpened, Some(report.clone()))
                .await
                .unwrap();
            assert_eq!(
                receiver.got(Action::RingEdgeOpened).await.last(),
                Some(&report)
            );
            let again = opener
                .send(&ctx, Some(id), Action::RingEdgeOpened, Some(report.clone()))
                .await;
            assert_eq!(refused(again), CantDoReason::NotAllowedByStatus);

            assert_eq!(parties[0].count(Action::RingClosed).await, 0);
            receiver
                .send(
                    &ctx,
                    Some(id),
                    Action::RingEdgeVerified,
                    Some(report.clone()),
                )
                .await
                .unwrap();
            assert_eq!(
                opener.got(Action::RingEdgeVerified).await.last(),
                Some(&report)
            );
        }
        for party in &parties {
            assert_eq!(party.count(Action::RingEdgeOpened).await, 1);
            assert_eq!(party.count(Action::RingEdgeVerified).await, 1);
        }

        assert_eq!(status(&ctx, id).await, SUCCESS);
        for party in &parties {
            let closed = party.got(Action::RingClosed).await;
            assert_eq!(closed.len(), 1);
            let RingPayload::Closed(closed) = &closed[0] else {
                panic!("not a closing report");
            };
            closed.check(&ring).unwrap();
            assert!(closed.is_complete(&ring));
        }
        // A finished ring takes no more steps.
        let late = at(&parties, &ring, 0)
            .send(&ctx, Some(id), Action::RingEdgeOpened, Some(edge(&ring, 9)))
            .await;
        assert_eq!(refused(late), CantDoReason::NotAllowedByStatus);
    }

    #[tokio::test]
    async fn an_offer_needs_valid_terms_a_sane_lifetime_and_the_senders_own_binding() {
        let ctx = ctx().await;
        let creator = Party::new();
        let send = |offer: RingOffer| {
            let (ctx, creator) = (&ctx, &creator);
            async move {
                let offer = Some(RingPayload::Offer(offer));
                creator.send(ctx, None, Action::RingOffer, offer).await
            }
        };
        let good = creator.offer(3);

        let mut alone = good.clone();
        alone.slots = 1;
        let mut tiny = good.clone();
        tiny.capacity_sat = 1;
        let mut expired = good.clone();
        expired.expires_at = now() - 1;
        let mut forever = good.clone();
        forever.expires_at = now() + MAX_OFFER_LIFETIME_SECS + 3_600;
        for bad in [alone, tiny, expired, forever] {
            assert_eq!(refused(send(bad).await), CantDoReason::InvalidParameters);
        }
        // A binding of the node to someone else's key does not make the sender its operator.
        let mut borrowed = good.clone();
        borrowed.seat.binding = creator.binding_of(&Keys::generate());
        assert_eq!(refused(send(borrowed).await), CantDoReason::NotAuthorized);
        // An offer with an id is not a new offer.
        let with_id = creator
            .send(
                &ctx,
                Some(Uuid::new_v4()),
                Action::RingOffer,
                Some(RingPayload::Offer(good.clone())),
            )
            .await;
        assert_eq!(refused(with_id), CantDoReason::InvalidParameters);
        assert!(creator.inbox().await.is_empty());

        // One identity can only have so many rings waiting for members.
        for _ in 0..MAX_OPEN_RINGS_PER_CREATOR {
            offered(&ctx, &creator, 3).await;
        }
        assert_eq!(refused(send(good).await), CantDoReason::TooManyRequests);
    }

    #[tokio::test]
    async fn a_ring_never_has_more_members_than_slots_nor_the_same_member_twice() {
        let ctx = ctx().await;
        let (creator, second, third, late) =
            (Party::new(), Party::new(), Party::new(), Party::new());
        let id = offered(&ctx, &creator, 3).await;
        assert_eq!(taken(&ctx, id).await, 1);

        let unknown = second.take(&ctx, Uuid::new_v4()).await;
        assert_eq!(refused(unknown), CantDoReason::NotFound);
        // Someone else's binding; the creator again; a second identity on a node already in.
        let borrowed = RingSeat {
            binding: third.seat().binding,
            ..second.seat()
        };
        let result = second
            .send(
                &ctx,
                Some(id),
                Action::TakeRingSlot,
                Some(RingPayload::Take(borrowed)),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::NotAuthorized);
        assert_eq!(
            refused(creator.take(&ctx, id).await),
            CantDoReason::InvalidParameters
        );
        let same_node = Party {
            identity: Keys::generate(),
            trade: Keys::generate(),
            node: creator.node,
            bond_sat: 0,
        };
        assert_eq!(
            refused(same_node.take(&ctx, id).await),
            CantDoReason::InvalidParameters
        );
        // None of that took a slot.
        assert_eq!(taken(&ctx, id).await, 1);
        assert_eq!(status(&ctx, id).await, PENDING);

        second.take(&ctx, id).await.unwrap();
        assert_eq!(taken(&ctx, id).await, 2);
        assert_eq!(creator.count(Action::RingRoster).await, 0, "not full yet");
        assert_eq!(
            refused(second.take(&ctx, id).await),
            CantDoReason::InvalidParameters
        );
        third.take(&ctx, id).await.unwrap();
        assert_eq!(status(&ctx, id).await, COMMITTING);
        // Full: nobody else gets in, and the roster went to the three members only.
        assert_eq!(
            refused(late.take(&ctx, id).await),
            CantDoReason::NotAllowedByStatus
        );
        assert_eq!(taken(&ctx, id).await, 3);
        assert!(late.inbox().await.is_empty());
        for member in [&creator, &second, &third] {
            assert_eq!(member.count(Action::RingRoster).await, 1);
        }
    }

    #[tokio::test]
    async fn a_commit_must_be_a_members_own_signature_of_this_ring() {
        let ctx = ctx().await;
        let parties = [Party::new(), Party::new()];
        let stranger = Party::new();
        let (id, ring) = filled(&ctx, &parties).await;

        assert_eq!(
            refused(commit(&ctx, id, &stranger, &ring).await),
            CantDoReason::IsNotYourOrder
        );
        // Another member's signature under the sender's name.
        let forged = Some(RingPayload::Commit(RingCommit::sign(
            &ring,
            &parties[1].identity,
        )));
        let result = parties[0]
            .send(&ctx, Some(id), Action::RingCommit, forged)
            .await;
        assert_eq!(refused(result), CantDoReason::InvalidSignature);
        // A commit to another ring.
        let mut other = ring.clone();
        other.created_at += 1;
        assert_eq!(
            refused(commit(&ctx, id, &parties[0], &other).await),
            CantDoReason::InvalidParameters
        );
        // A channel report before the ring is open.
        let early = parties[0]
            .send(&ctx, Some(id), Action::RingEdgeOpened, Some(edge(&ring, 1)))
            .await;
        assert_eq!(refused(early), CantDoReason::NotAllowedByStatus);
        assert_eq!(status(&ctx, id).await, COMMITTING);
        assert_eq!(parties[0].count(Action::RingOpen).await, 0);

        // A commit on a ring that is still filling.
        let filling = offered(&ctx, &parties[0], 3).await;
        assert_eq!(
            refused(commit(&ctx, filling, &parties[0], &ring).await),
            CantDoReason::NotAllowedByStatus
        );
    }

    #[tokio::test]
    async fn a_channel_counts_only_when_the_member_it_was_opened_to_confirms_that_outpoint() {
        let ctx = ctx().await;
        let parties = [Party::new(), Party::new(), Party::new()];
        let stranger = Party::new();
        let (id, ring) = opened(&ctx, &parties).await;
        let (opener, receiver, third) = (
            at(&parties, &ring, 0),
            at(&parties, &ring, 1),
            at(&parties, &ring, 2),
        );
        let report = edge(&ring, 1);

        // Nothing to confirm before the opener has reported.
        let result = receiver
            .send(
                &ctx,
                Some(id),
                Action::RingEdgeVerified,
                Some(report.clone()),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::InvalidParameters);
        let result = stranger
            .send(&ctx, Some(id), Action::RingEdgeOpened, Some(report.clone()))
            .await;
        assert_eq!(refused(result), CantDoReason::IsNotYourOrder);
        let mut other = ring.clone();
        other.created_at += 1;
        let result = opener
            .send(
                &ctx,
                Some(id),
                Action::RingEdgeOpened,
                Some(edge(&other, 1)),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::InvalidParameters);

        opener
            .send(&ctx, Some(id), Action::RingEdgeOpened, Some(report.clone()))
            .await
            .unwrap();
        assert_eq!(receiver.count(Action::RingEdgeOpened).await, 1);
        assert_eq!(third.count(Action::RingEdgeOpened).await, 0);

        // Another outpoint than the one reported; the opener confirming itself; a member the
        // channel was not opened to.
        let result = receiver
            .send(
                &ctx,
                Some(id),
                Action::RingEdgeVerified,
                Some(edge(&ring, 2)),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::InvalidParameters);
        for other in [opener, third] {
            let result = other
                .send(
                    &ctx,
                    Some(id),
                    Action::RingEdgeVerified,
                    Some(report.clone()),
                )
                .await;
            assert_eq!(refused(result), CantDoReason::InvalidParameters);
        }
        assert_eq!(opener.count(Action::RingEdgeVerified).await, 0);

        receiver
            .send(
                &ctx,
                Some(id),
                Action::RingEdgeVerified,
                Some(report.clone()),
            )
            .await
            .unwrap();
        assert_eq!(opener.count(Action::RingEdgeVerified).await, 1);
        let again = receiver
            .send(&ctx, Some(id), Action::RingEdgeVerified, Some(report))
            .await;
        assert_eq!(refused(again), CantDoReason::NotAllowedByStatus);
        assert_eq!(
            status(&ctx, id).await,
            OPEN,
            "two channels are still missing"
        );
    }

    #[tokio::test]
    async fn a_ring_can_be_withdrawn_or_left_only_while_its_slots_are_open() {
        let ctx = ctx().await;
        let (creator, member, stranger, another) =
            (Party::new(), Party::new(), Party::new(), Party::new());
        let id = offered(&ctx, &creator, 3).await;
        member.take(&ctx, id).await.unwrap();

        let result = stranger.send(&ctx, Some(id), Action::Cancel, None).await;
        assert_eq!(refused(result), CantDoReason::IsNotYourOrder);
        // A member leaves: its slot is free again, the ring stays open, the others hear nothing.
        member
            .send(&ctx, Some(id), Action::Cancel, None)
            .await
            .unwrap();
        assert_eq!(taken(&ctx, id).await, 1);
        assert_eq!(status(&ctx, id).await, PENDING);
        assert_eq!(member.count(Action::Canceled).await, 1);
        assert_eq!(creator.count(Action::Canceled).await, 0);
        another.take(&ctx, id).await.unwrap();
        member.take(&ctx, id).await.unwrap();
        assert_eq!(status(&ctx, id).await, COMMITTING);
        // Once the roster is fixed nobody backs out.
        for party in [&creator, &member, &another] {
            let result = party.send(&ctx, Some(id), Action::Cancel, None).await;
            assert_eq!(refused(result), CantDoReason::NotAllowedByStatus);
        }

        // The creator withdraws a ring that is still filling: every member is told.
        let open = offered(&ctx, &creator, 3).await;
        member.take(&ctx, open).await.unwrap();
        let before = member.count(Action::Canceled).await;
        creator
            .send(&ctx, Some(open), Action::Cancel, None)
            .await
            .unwrap();
        assert_eq!(status(&ctx, open).await, CANCELED);
        assert_eq!(member.count(Action::Canceled).await, before + 1);
        assert_eq!(creator.count(Action::Canceled).await, 1);
        let again = creator.send(&ctx, Some(open), Action::Cancel, None).await;
        assert_eq!(refused(again), CantDoReason::OrderAlreadyCanceled);
        assert_eq!(
            refused(another.take(&ctx, open).await),
            CantDoReason::NotAllowedByStatus
        );
    }

    type Sent = Arc<std::sync::Mutex<Vec<Event>>>;

    fn sender(sent: &Sent) -> impl FnMut(Event) -> std::future::Ready<Result<(), MostroError>> {
        let sent = sent.clone();
        move |event| {
            sent.lock().unwrap().push(event);
            std::future::ready(Ok(()))
        }
    }

    /// One housekeeping pass at `at`: the ring orders it published, as (status, slots taken).
    async fn pass_at(ctx: &AppContext, at: u64) -> Vec<(Uuid, RingOrderStatus, u8)> {
        let sent = Sent::default();
        housekeeping_pass_with(ctx.pool(), ctx.keys(), at, sender(&sent))
            .await
            .unwrap();
        let events = sent.lock().unwrap();
        let published = events
            .iter()
            .map(|event| {
                assert_eq!(event.pubkey, ctx.keys().public_key());
                let order = RingOrder::from_event(event).unwrap();
                (order.id, order.status, order.taken)
            })
            .collect();
        published
    }

    #[tokio::test]
    async fn housekeeping_expires_unfilled_rings_closes_overdue_ones_and_publishes_orders() {
        let ctx = ctx().await;
        let t = now();

        // The order event follows the slots and the status.
        let (creator, member) = (Party::new(), Party::new());
        let filling = offered(&ctx, &creator, 3).await;
        assert_eq!(
            pass_at(&ctx, t).await,
            vec![(filling, RingOrderStatus::Pending, 1)]
        );
        assert!(pass_at(&ctx, t).await.is_empty(), "nothing is behind now");
        member.take(&ctx, filling).await.unwrap();
        assert_eq!(
            pass_at(&ctx, t).await,
            vec![(filling, RingOrderStatus::Pending, 2)]
        );

        // A ring that fills, opens and gets one channel confirmed.
        let parties = [Party::new(), Party::new(), Party::new()];
        let (id, ring) = opened(&ctx, &parties).await;
        assert_eq!(
            pass_at(&ctx, t).await,
            vec![(id, RingOrderStatus::InProgress, 3)]
        );
        let report = edge(&ring, 1);
        at(&parties, &ring, 0)
            .send(&ctx, Some(id), Action::RingEdgeOpened, Some(report.clone()))
            .await
            .unwrap();
        at(&parties, &ring, 1)
            .send(&ctx, Some(id), Action::RingEdgeVerified, Some(report))
            .await
            .unwrap();
        // A second channel is reported and never confirmed.
        at(&parties, &ring, 1)
            .send(&ctx, Some(id), Action::RingEdgeOpened, Some(edge(&ring, 2)))
            .await
            .unwrap();

        // An hour on nothing has changed.
        assert!(pass_at(&ctx, t + 3_600).await.is_empty());
        assert_eq!(status(&ctx, id).await, OPEN);
        assert_eq!(status(&ctx, filling).await, PENDING);

        // Past the offers' expiry: the unfilled ring expires and its two members are told. The
        // full ring is still inside its window. Nothing is published after the expiry.
        let expiry = creator.offer(3).expires_at + 60;
        assert!(pass_at(&ctx, expiry).await.is_empty());
        assert_eq!(status(&ctx, filling).await, EXPIRED);
        assert_eq!(creator.count(Action::Canceled).await, 1);
        assert_eq!(member.count(Action::Canceled).await, 1);
        assert_eq!(status(&ctx, id).await, OPEN);
        assert_eq!(
            refused(Party::new().take(&ctx, filling).await),
            CantDoReason::NotAllowedByStatus
        );

        // Past the window: the ring closes as partial, and every member learns that only the
        // first member's channel was confirmed.
        pass_at(&ctx, ring.window_ends_at() + 60).await;
        assert_eq!(status(&ctx, id).await, PARTIAL);
        for party in &parties {
            let closed = party.got(Action::RingClosed).await;
            assert_eq!(closed.len(), 1);
            let RingPayload::Closed(closed) = &closed[0] else {
                panic!("not a closing report");
            };
            closed.check(&ring).unwrap();
            assert_eq!(closed.verified, vec![0]);
            assert!(!closed.is_complete(&ring));
        }
        // A second pass tells nobody again, and a closed ring takes no more reports.
        pass_at(&ctx, ring.window_ends_at() + 120).await;
        assert_eq!(parties[0].count(Action::RingClosed).await, 1);
        let late = at(&parties, &ring, 2)
            .send(&ctx, Some(id), Action::RingEdgeOpened, Some(edge(&ring, 3)))
            .await;
        assert_eq!(refused(late), CantDoReason::NotAllowedByStatus);
    }

    #[tokio::test]
    async fn the_instances_own_messages_are_refused_and_maintenance_takes_no_new_rings() {
        let ctx = ctx().await;
        let parties = [Party::new(), Party::new()];
        let (id, ring) = filled(&ctx, &parties).await;

        // A member cannot send the roster, the commits or the closing report.
        let roster = parties[0].got(Action::RingRoster).await.remove(0);
        let closed = RingPayload::Closed(RingClosed {
            ring_id: ring.id(),
            verified: vec![0, 1],
            slashed: vec![],
        });
        let open = RingPayload::Open(RingOpen {
            ring_id: ring.id(),
            commits: vec![],
        });
        for (action, payload) in [
            (Action::RingRoster, roster),
            (Action::RingClosed, closed),
            (Action::RingOpen, open),
        ] {
            let result = parties[0].send(&ctx, Some(id), action, Some(payload)).await;
            assert_eq!(refused(result), CantDoReason::InvalidAction);
        }
        assert_eq!(status(&ctx, id).await, COMMITTING);

        // An id that is not a ring stays on the escrow cancel path.
        let fiat = Message::new_order(Some(Uuid::new_v4()), None, None, Action::Cancel, None);
        assert!(!names_a_ring(&ctx, &fiat).await);

        let filling = offered(&ctx, &parties[0], 3).await;
        ctx.maintenance().set(ctx.pool(), true, None).await.unwrap();
        let offer = Some(RingPayload::Offer(parties[0].offer(3)));
        let result = parties[0].send(&ctx, None, Action::RingOffer, offer).await;
        assert_eq!(refused(result), CantDoReason::MaintenanceMode);
        assert_eq!(
            refused(parties[1].take(&ctx, filling).await),
            CantDoReason::MaintenanceMode
        );
        // A ring under way goes on.
        commit(&ctx, id, &parties[0], &ring).await.unwrap();
        commit(&ctx, id, &parties[1], &ring).await.unwrap();
        assert_eq!(status(&ctx, id).await, OPEN);
    }

    // ---- bonds -------------------------------------------------------------------------------

    /// What every member of a bonded test ring locks.
    const BOND: u64 = 50_000;

    /// The outpoint [`edge`] reports for `n`.
    fn outpoint(n: u8) -> String {
        format!("{}:{n}", format!("{n:02x}").repeat(32))
    }

    fn node_of(party: &Party) -> String {
        party.node_key().to_string()
    }

    /// The payment hash of the one bond invoice a party was sent. The simulated node's invoices
    /// are `lnbcrt1` followed by the hash.
    async fn bond_hash(party: &Party) -> String {
        let invoices = party.got(Action::RingBondInvoice).await;
        assert_eq!(invoices.len(), 1, "one bond invoice");
        let RingPayload::Invoice(invoice) = &invoices[0] else {
            panic!("not an invoice");
        };
        invoice.validate().unwrap();
        invoice
            .invoice
            .strip_prefix("lnbcrt1")
            .expect("a simulated invoice")
            .to_string()
    }

    /// One pass over the bonds at `at`, on the simulated node every test shares.
    async fn bonds_pass(ctx: &AppContext, at: u64) {
        bond_pass(ctx.pool(), &*testing::shared(), at)
            .await
            .unwrap();
    }

    /// A full ring with every commit in, waiting for its bonds. Returns the bond hashes in the
    /// order of `parties`.
    async fn bonding(ctx: &AppContext, parties: &[Party]) -> (Uuid, Ring, Vec<String>) {
        let (id, ring) = filled(ctx, parties).await;
        assert_eq!(ring.terms.bond_sat, BOND);
        for party in parties {
            commit(ctx, id, party, &ring).await.unwrap();
        }
        assert_eq!(status(ctx, id).await, BONDING);
        let mut hashes = Vec::new();
        for party in parties {
            hashes.push(bond_hash(party).await);
        }
        (id, ring, hashes)
    }

    /// A ring with bonds, every bond paid and seen: open.
    async fn bonded(ctx: &AppContext, parties: &[Party]) -> (Uuid, Ring, Vec<String>) {
        let (id, ring, hashes) = bonding(ctx, parties).await;
        for hash in &hashes {
            testing::shared().pay(hash);
        }
        bonds_pass(ctx, now()).await;
        assert_eq!(status(ctx, id).await, OPEN);
        (id, ring, hashes)
    }

    /// The states of a ring's bonds, in roster order.
    async fn bond_states(
        ctx: &AppContext,
        id: Uuid,
        parties: &[Party],
        ring: &Ring,
    ) -> Vec<String> {
        let bonds = liquidity_bond::of_order(ctx.pool(), RING, id)
            .await
            .unwrap();
        (0..ring.members.len())
            .map(|position| {
                let who = at(parties, ring, position).identity.public_key().to_hex();
                let bond = bonds
                    .iter()
                    .find(|bond| bond.payer_identity == who)
                    .expect("a bond");
                bond.state.clone()
            })
            .collect()
    }

    /// The closing report a party was sent.
    async fn closed_of(party: &Party) -> RingClosed {
        let closed = party.got(Action::RingClosed).await;
        assert_eq!(closed.len(), 1, "one closing report");
        match &closed[0] {
            RingPayload::Closed(closed) => closed.clone(),
            _ => panic!("not a closing report"),
        }
    }

    fn claim_with(ring_id: String, invoice: &str) -> Option<RingPayload> {
        Some(RingPayload::Invoice(RingInvoice {
            ring_id,
            invoice: invoice.to_string(),
        }))
    }

    async fn report(ctx: &AppContext, id: Uuid, who: &Party, action: Action, what: RingPayload) {
        who.send(ctx, Some(id), action, Some(what)).await.unwrap();
    }

    #[tokio::test]
    async fn a_ring_with_bonds_opens_only_when_every_bond_is_locked_and_gives_them_all_back() {
        let ctx = ctx().await;
        let node = testing::shared();
        let parties = [Party::bonded(), Party::new(), Party::new()];
        let (id, ring, hashes) = bonding(&ctx, &parties).await;
        for (party, hash) in parties.iter().zip(&hashes) {
            assert_eq!(node.hold(hash), Some(HoldState::Open));
            assert_eq!(party.count(Action::RingOpen).await, 0);
        }

        // Two of three bonds paid: nobody is told to open, and nobody is sent a second invoice.
        node.pay(&hashes[0]);
        node.pay(&hashes[1]);
        bonds_pass(&ctx, now()).await;
        assert_eq!(status(&ctx, id).await, BONDING);
        for party in &parties {
            assert_eq!(party.count(Action::RingBondInvoice).await, 1);
            assert_eq!(party.count(Action::RingOpen).await, 0);
        }
        // A channel report is not taken yet.
        let early = at(&parties, &ring, 0)
            .send(&ctx, Some(id), Action::RingEdgeOpened, Some(edge(&ring, 1)))
            .await;
        assert_eq!(refused(early), CantDoReason::NotAllowedByStatus);

        node.pay(&hashes[2]);
        bonds_pass(&ctx, now()).await;
        assert_eq!(status(&ctx, id).await, OPEN);
        bonds_pass(&ctx, now()).await;
        for party in &parties {
            assert_eq!(party.count(Action::RingOpen).await, 1);
        }
        assert_eq!(
            bond_states(&ctx, id, &parties, &ring).await,
            vec![liquidity_bond::LOCKED; 3]
        );

        // Every member opens and every channel is confirmed: every bond goes back.
        for n in 0..3u8 {
            let (opener, receiver) = (
                at(&parties, &ring, usize::from(n)),
                at(&parties, &ring, usize::from(n) + 1),
            );
            let what = edge(&ring, n + 1);
            report(&ctx, id, opener, Action::RingEdgeOpened, what.clone()).await;
            report(&ctx, id, receiver, Action::RingEdgeVerified, what).await;
        }
        assert_eq!(status(&ctx, id).await, SUCCESS);
        for hash in &hashes {
            assert_eq!(node.hold(hash), Some(HoldState::Canceled));
        }
        assert_eq!(
            bond_states(&ctx, id, &parties, &ring).await,
            vec![liquidity_bond::RELEASED; 3]
        );
        for party in &parties {
            let closed = closed_of(party).await;
            closed.check(&ring).unwrap();
            assert!(closed.is_complete(&ring));
            assert!(closed.slashed.is_empty());
        }
        // Nothing was taken, so nothing can be claimed.
        let (invoice, _) = testing::invoice(payout_sat(BOND) * 1_000, 3_600);
        let claim = at(&parties, &ring, 0)
            .send(
                &ctx,
                Some(id),
                Action::RingBondClaim,
                claim_with(ring.id(), &invoice),
            )
            .await;
        assert_eq!(refused(claim), CantDoReason::NotAllowedByStatus);
        bonds_pass(&ctx, now()).await;
        assert!(!node.sent().iter().any(|(sent, _)| sent == &invoice));
    }

    #[tokio::test]
    async fn a_bond_that_is_not_paid_in_time_cancels_the_ring_and_frees_the_others() {
        let ctx = ctx().await;
        let node = testing::shared();
        let parties = [Party::bonded(), Party::new(), Party::new()];
        let (id, ring, hashes) = bonding(&ctx, &parties).await;
        node.pay(&hashes[0]);
        node.pay(&hashes[1]);
        bonds_pass(&ctx, now() + BOND_PAY_WINDOW_SECS - 30).await;
        assert_eq!(status(&ctx, id).await, BONDING);
        bonds_pass(&ctx, now() + BOND_PAY_WINDOW_SECS + 1).await;
        assert_eq!(status(&ctx, id).await, CANCELED);
        for (party, hash) in parties.iter().zip(&hashes) {
            assert_eq!(node.hold(hash), Some(HoldState::Canceled));
            assert_eq!(party.count(Action::Canceled).await, 1);
            assert_eq!(party.count(Action::RingOpen).await, 0);
        }
        assert_eq!(
            bond_states(&ctx, id, &parties, &ring).await,
            vec![liquidity_bond::RELEASED; 3]
        );
        // The third member pays too late: the invoice is gone.
        bonds_pass(&ctx, now() + BOND_PAY_WINDOW_SECS + 60).await;
        assert_eq!(status(&ctx, id).await, CANCELED);

        // Bonds that are all locked, but seen only after the window: nobody is told to open a
        // ring that is already over. It is canceled and every bond goes back.
        let parties = [Party::bonded(), Party::new()];
        let (id, ring, hashes) = bonding(&ctx, &parties).await;
        node.pay(&hashes[0]);
        node.pay(&hashes[1]);
        bonds_pass(&ctx, ring.window_ends_at()).await;
        assert_eq!(status(&ctx, id).await, CANCELED);
        for (party, hash) in parties.iter().zip(&hashes) {
            assert_eq!(node.hold(hash), Some(HoldState::Canceled));
            assert_eq!(party.count(Action::RingOpen).await, 0);
        }

        // The node letting one locked payment go ends the ring the same way.
        let parties = [Party::bonded(), Party::new()];
        let (id, ring, hashes) = bonding(&ctx, &parties).await;
        node.pay(&hashes[0]);
        node.pay(&hashes[1]);
        node.time_out(&hashes[1]);
        bonds_pass(&ctx, now()).await;
        assert_eq!(status(&ctx, id).await, CANCELED);
        assert_eq!(node.hold(&hashes[0]), Some(HoldState::Canceled));
        assert_eq!(
            bond_states(&ctx, id, &parties, &ring).await,
            vec![liquidity_bond::RELEASED; 2]
        );
    }

    #[tokio::test]
    async fn when_the_window_ends_a_missing_channel_costs_its_opener_the_bond() {
        let ctx = ctx().await;
        let node = testing::shared();
        let parties = [Party::bonded(), Party::new(), Party::new()];
        let (id, ring, _) = bonded(&ctx, &parties).await;
        let (m0, m1, m2) = (
            at(&parties, &ring, 0),
            at(&parties, &ring, 1),
            at(&parties, &ring, 2),
        );
        let hash = |party: &Party| {
            let who = party.identity.public_key().to_hex();
            let pool = ctx.pool().clone();
            async move {
                let bonds = liquidity_bond::of_order(&pool, RING, id).await.unwrap();
                let bond = bonds.iter().find(|bond| bond.payer_identity == who);
                bond.expect("a bond").payment_hash.clone()
            }
        };
        let (h0, h1, h2) = (hash(m0).await, hash(m1).await, hash(m2).await);

        // m0 opens to m1, who confirms. m1 opens to m2, who stays silent, but the graph shows
        // the channel. m2 never opens.
        report(&ctx, id, m0, Action::RingEdgeOpened, edge(&ring, 1)).await;
        report(&ctx, id, m1, Action::RingEdgeVerified, edge(&ring, 1)).await;
        report(&ctx, id, m1, Action::RingEdgeOpened, edge(&ring, 2)).await;
        node.announce(&node_of(m1), &node_of(m2), 2_000_000, &outpoint(2));

        // Before the window ends nothing is decided, by either pass.
        let end = ring.window_ends_at();
        bonds_pass(&ctx, end - 1).await;
        assert_eq!(status(&ctx, id).await, OPEN);
        assert_eq!(
            bond_states(&ctx, id, &parties, &ring).await,
            vec![liquidity_bond::LOCKED; 3]
        );
        // The pass that has no node leaves a ring with bonds alone, even overdue.
        pass_at(&ctx, end).await;
        assert_eq!(status(&ctx, id).await, OPEN);

        // A node that says it is not synced yet: nothing is decided, the ring stays open.
        let lagging = MockNode::new();
        lagging.set_unsynced(true);
        bond_pass(ctx.pool(), &*lagging, end)
            .await
            .expect("a pass that waits");
        assert_eq!(status(&ctx, id).await, OPEN);
        assert_eq!(
            bond_states(&ctx, id, &parties, &ring).await,
            vec![liquidity_bond::LOCKED; 3]
        );

        // A node that cannot be asked: the bond that needs no graph (its channel was confirmed)
        // goes back; the two that need the graph stay locked and the ring stays open.
        let blind = MockNode::new();
        blind.set_down(true);
        assert!(bond_pass(ctx.pool(), &*blind, end).await.is_err());
        assert_eq!(status(&ctx, id).await, OPEN);
        assert_eq!(
            bond_states(&ctx, id, &parties, &ring).await,
            vec![
                liquidity_bond::RELEASED,
                liquidity_bond::LOCKED,
                liquidity_bond::LOCKED
            ]
        );
        assert_eq!(node.hold(&h2), Some(HoldState::Accepted));
        for party in &parties {
            assert_eq!(party.count(Action::RingClosed).await, 0);
        }

        bonds_pass(&ctx, end).await;
        assert_eq!(status(&ctx, id).await, PARTIAL);
        assert_eq!(
            bond_states(&ctx, id, &parties, &ring).await,
            vec![
                liquidity_bond::RELEASED,
                liquidity_bond::RELEASED,
                liquidity_bond::SLASHED
            ]
        );
        assert_eq!(node.hold(&h0), Some(HoldState::Canceled));
        assert_eq!(node.hold(&h1), Some(HoldState::Canceled));
        assert_eq!(node.hold(&h2), Some(HoldState::Settled));
        for party in &parties {
            let closed = closed_of(party).await;
            closed.check(&ring).unwrap();
            assert_eq!(closed.verified, vec![0]);
            assert_eq!(closed.slashed, vec![2]);
            // m2 should have opened to m0: m0 is owed, nobody else.
            assert!(closed.owed_a_bond(&ring, 0));
            assert!(!closed.owed_a_bond(&ring, 1) && !closed.owed_a_bond(&ring, 2));
        }

        // Only m0 can claim it, for this ring, and it is paid once.
        let (invoice, _) = testing::invoice(payout_sat(BOND) * 1_000, 3_600);
        for other in [m1, m2, &Party::new()] {
            let claim = other
                .send(
                    &ctx,
                    Some(id),
                    Action::RingBondClaim,
                    claim_with(ring.id(), &invoice),
                )
                .await;
            assert_eq!(refused(claim), CantDoReason::IsNotYourOrder);
        }
        let elsewhere = m0
            .send(
                &ctx,
                Some(id),
                Action::RingBondClaim,
                claim_with("ef".repeat(32), &invoice),
            )
            .await;
        assert_eq!(refused(elsewhere), CantDoReason::InvalidParameters);
        m0.send(
            &ctx,
            Some(id),
            Action::RingBondClaim,
            claim_with(ring.id(), &invoice),
        )
        .await
        .unwrap();
        bonds_pass(&ctx, now()).await;
        bonds_pass(&ctx, now()).await;
        assert_eq!(
            bond_states(&ctx, id, &parties, &ring).await[2],
            liquidity_bond::PAID
        );
        let payments: Vec<_> = node
            .sent()
            .into_iter()
            .filter(|(sent, _)| sent == &invoice)
            .collect();
        assert_eq!(payments, vec![(invoice, routing_reserve_sat(BOND) * 1_000)]);
        let (again, _) = testing::invoice(payout_sat(BOND) * 1_000, 3_600);
        let twice = m0
            .send(
                &ctx,
                Some(id),
                Action::RingBondClaim,
                claim_with(ring.id(), &again),
            )
            .await;
        assert_eq!(refused(twice), CantDoReason::NotAllowedByStatus);
    }

    #[tokio::test]
    async fn only_a_new_channel_of_its_own_saves_a_members_bond() {
        let ctx = ctx().await;
        let node = testing::shared();

        // A ring of two: one channel between the two nodes is one member's opening, not both's.
        let parties = [Party::bonded(), Party::new()];
        let (id, ring, _) = bonded(&ctx, &parties).await;
        let (a, b) = (at(&parties, &ring, 0), at(&parties, &ring, 1));
        report(&ctx, id, a, Action::RingEdgeOpened, edge(&ring, 1)).await;
        node.announce(&node_of(a), &node_of(b), 2_000_000, &outpoint(1));
        // b cannot pass a's channel off as its own.
        let copied = b
            .send(&ctx, Some(id), Action::RingEdgeOpened, Some(edge(&ring, 1)))
            .await;
        assert_eq!(refused(copied), CantDoReason::InvalidParameters);
        bonds_pass(&ctx, ring.window_ends_at()).await;
        assert_eq!(status(&ctx, id).await, PARTIAL);
        assert_eq!(
            bond_states(&ctx, id, &parties, &ring).await,
            vec![liquidity_bond::RELEASED, liquidity_bond::SLASHED]
        );
        let closed = closed_of(a).await;
        assert!(closed.verified.is_empty());
        assert_eq!(closed.slashed, vec![1]);
        assert!(closed.owed_a_bond(&ring, 0));

        // A ring of three where nobody opens a channel that counts.
        let parties = [Party::bonded(), Party::new(), Party::new()];
        let (id, ring, hashes) = bonding(&ctx, &parties).await;
        let (m0, m1, m2) = (
            at(&parties, &ring, 0),
            at(&parties, &ring, 1),
            at(&parties, &ring, 2),
        );
        // m1 and m2 already have a channel of the ring's capacity when the bonds lock.
        node.announce(&node_of(m1), &node_of(m2), 2_000_000, "0ld:0");
        for hash in &hashes {
            node.pay(hash);
        }
        bonds_pass(&ctx, now()).await;
        assert_eq!(status(&ctx, id).await, OPEN);
        // m0 opens a channel to m1 of the wrong size.
        node.announce(&node_of(m0), &node_of(m1), 1_999_999, "5ma11:0");
        // m2 reports one channel; the graph shows another.
        report(&ctx, id, m2, Action::RingEdgeOpened, edge(&ring, 3)).await;
        node.announce(&node_of(m2), &node_of(m0), 2_000_000, "0ther:1");
        bonds_pass(&ctx, ring.window_ends_at()).await;
        assert_eq!(status(&ctx, id).await, PARTIAL);
        assert_eq!(
            bond_states(&ctx, id, &parties, &ring).await,
            vec![liquidity_bond::SLASHED; 3]
        );
        let closed = closed_of(m0).await;
        closed.check(&ring).unwrap();
        assert!(closed.verified.is_empty());
        assert_eq!(closed.slashed, vec![0, 1, 2]);
        // Each bond is owed to the member its payer should have opened to.
        let bonds = liquidity_bond::of_order(ctx.pool(), RING, id)
            .await
            .unwrap();
        for (payer, owed) in [(m0, m1), (m1, m2), (m2, m0)] {
            let bond = bonds
                .iter()
                .find(|bond| bond.payer_identity == payer.identity.public_key().to_hex())
                .unwrap();
            assert_eq!(
                bond.recipient_identity,
                Some(owed.identity.public_key().to_hex())
            );
        }
    }

    #[tokio::test]
    async fn a_bond_above_the_instances_limit_and_the_instances_own_bond_messages_are_refused() {
        let ctx = ctx().await;
        // The instance's limit is a million satoshi; the terms themselves allow this bond.
        let mut greedy = Party::bonded();
        greedy.bond_sat = 1_500_000;
        let offer = greedy.offer(3);
        offer.validate().unwrap();
        let result = greedy
            .send(
                &ctx,
                None,
                Action::RingOffer,
                Some(RingPayload::Offer(offer)),
            )
            .await;
        assert_eq!(refused(result), CantDoReason::OutOfRangeSatsAmount);

        // A member cannot send a bond invoice, and a ring without bonds owes nobody one.
        let parties = [Party::new(), Party::new()];
        let (id, ring) = opened(&ctx, &parties).await;
        let (invoice, _) = testing::invoice(payout_sat(BOND) * 1_000, 3_600);
        let forged = parties[0]
            .send(
                &ctx,
                Some(id),
                Action::RingBondInvoice,
                claim_with(ring.id(), &invoice),
            )
            .await;
        assert_eq!(refused(forged), CantDoReason::InvalidAction);
        pass_at(&ctx, ring.window_ends_at()).await;
        assert_eq!(status(&ctx, id).await, PARTIAL);
        let claim = parties[0]
            .send(
                &ctx,
                Some(id),
                Action::RingBondClaim,
                claim_with(ring.id(), &invoice),
            )
            .await;
        assert_eq!(refused(claim), CantDoReason::IsNotYourOrder);
        assert!(closed_of(&parties[0]).await.slashed.is_empty());
    }
}
