//! bipnip: bonds on liquidity orders (bipnip repo, `docs/nips/liquidity-rings.md`).
//!
//! This is the only place where the liquidity side of an instance holds anyone's money. A bond
//! is a hold invoice on this instance's own node. A member pays it before anything is opened;
//! the payment stays locked, and one of two things ends it:
//!
//! - the member did what it signed up for: the invoice is cancelled and the payment goes back
//!   (`released`);
//! - it did not: the invoice is settled (`slashed`) and the amount, less a routing reserve, is
//!   paid on to the member that was let down, against an invoice that member sends (`claimed`,
//!   then `paid`). A bond nobody claims within seven days stays with the instance (`forfeited`).
//!
//! ```text
//! requested -> locked -> released
//!     |           \----> slashed -> claimed -> paid
//!     \-> released          |  ^------/ (the payout failed; a new invoice may be sent)
//!                           \-> forfeited
//! ```
//!
//! Rules this module keeps, whatever its callers do:
//!
//! - Every change of state is a compare-and-swap on the row, and the row changes **before** the
//!   node is told. A crash in between leaves `node_done = 0`, and the housekeeping pass repeats
//!   the node call, which is safe to repeat. The node is never asked to settle a bond the
//!   database does not already show as taken.
//! - A bond is settled only from `locked`, and only once.
//! - A payout goes to the one identity recorded when the bond was taken, for exactly
//!   [`mostro_core::bond::payout_sat`], with the routing fee capped at the reserve. It is sent
//!   only when the node has no record of a payment for that invoice, and a new invoice is
//!   accepted only after the node reported the last payment as failed. So one bond is never
//!   paid out twice.
//! - When the node is unreachable nothing is decided: no bond is taken or let go on a guess.
//!
//! Who is let down, and on what evidence, is not decided here: see `app::ring`. Mostro's own
//! bond code and tables (`app::bond`) are separate and untouched.

use crate::lightning::invoice::{decode_invoice, validate_payout_invoice};
use bipnip_ln::{BackendError, HoldInvoiceRequest, HoldState, LightningBackend, PaymentState};
use bitcoin::hashes::{sha256, Hash};
use mostro_core::bond::{payout_sat, routing_reserve_sat, BOND_CLAIM_WINDOW_SECS};
use mostro_core::node_binding::{Action as BindingAction, Network, SignedStatement, Statement};
use mostro_core::prelude::*;
use nostr_sdk::prelude::{Event, FinalizeEvent, Keys};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

/// A bond of a ring member.
pub const RING: &str = "ring";
/// The bond of a lease's buyer.
pub const LEASE: &str = "lease";

/// The invoice was sent; the payment has not arrived.
pub const REQUESTED: &str = "requested";
/// The payment is locked at this instance's node.
pub const LOCKED: &str = "locked";
/// Cancelled: the payment went back, or never came.
pub const RELEASED: &str = "released";
/// Taken, and owed to `recipient_identity`.
pub const SLASHED: &str = "slashed";
/// The recipient sent an invoice; the payout is under way.
pub const CLAIMED: &str = "claimed";
/// Paid on to the recipient.
pub const PAID: &str = "paid";
/// Taken and never claimed in time.
pub const FORFEITED: &str = "forfeited";

/// How long a member has to pay its bond invoice.
pub const BOND_PAY_WINDOW_SECS: u64 = 3_600;
/// Most payouts tried for one bond.
const MAX_PAYOUT_ATTEMPTS: i64 = 10;
/// A claim invoice must stay payable at least this long.
const MIN_CLAIM_INVOICE_LIFE_SECS: u64 = 600;
/// How long one housekeeping pass waits for a payout to finish.
const PAYOUT_WAIT_SECS: u32 = 20;

/// The `[liquidity]` section of `settings.toml`. Absent ≡ no bonds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquiditySettings {
    /// Take bonds on rings. Off by default: with it on, this instance's node holds members'
    /// payments for up to the ring's window.
    #[serde(default)]
    pub bonds: bool,
    /// The largest bond a ring on this instance may ask of each member, or a lease of its
    /// buyer, in satoshi.
    #[serde(default = "default_max_bond_sat")]
    pub max_bond_sat: u64,
    /// How long a lease buyer's bond may stay locked, in seconds, counted from the take: the
    /// time the lease has to become active. One minute to 48 hours; 48 hours by default, the
    /// longest a lease's own hold invoice lives.
    #[serde(default = "default_lease_bond_window_secs")]
    pub lease_bond_window_secs: u64,
}

fn default_max_bond_sat() -> u64 {
    1_000_000
}

fn default_lease_bond_window_secs() -> u64 {
    48 * 3_600
}

impl Default for LiquiditySettings {
    fn default() -> Self {
        LiquiditySettings {
            bonds: false,
            max_bond_sat: default_max_bond_sat(),
            lease_bond_window_secs: default_lease_bond_window_secs(),
        }
    }
}

/// Only the section this module reads; every other section belongs to Mostro's own settings.
#[derive(serde::Deserialize)]
struct SettingsFile {
    #[serde(default)]
    liquidity: Option<LiquiditySettings>,
}

static SETTINGS: OnceLock<LiquiditySettings> = OnceLock::new();

/// Reads the `[liquidity]` section out of the text of `settings.toml`.
pub fn parse_settings(toml_text: &str) -> Result<LiquiditySettings, MostroError> {
    let file: SettingsFile = toml::from_str(toml_text)
        .map_err(|e| MostroInternalErr(ServiceError::IOError(format!("[liquidity]: {e}"))))?;
    let settings = file.liquidity.unwrap_or_default();
    if !(60..=default_lease_bond_window_secs()).contains(&settings.lease_bond_window_secs) {
        return Err(MostroInternalErr(ServiceError::IOError(
            "[liquidity]: lease_bond_window_secs must be 60 to 172800".to_string(),
        )));
    }
    Ok(settings)
}

/// Reads and keeps the `[liquidity]` section. Called once, when the settings file is loaded.
pub fn load_settings(toml_text: &str) -> Result<(), MostroError> {
    let settings = parse_settings(toml_text)?;
    let _ = SETTINGS.set(settings);
    Ok(())
}

/// The liquidity settings in force: those loaded at startup, else the defaults (no bonds).
#[cfg(not(test))]
pub fn settings() -> LiquiditySettings {
    SETTINGS.get().cloned().unwrap_or_default()
}

/// In tests, bonds are on unless a test says otherwise.
#[cfg(test)]
pub fn settings() -> LiquiditySettings {
    SETTINGS.get().cloned().unwrap_or(LiquiditySettings {
        bonds: true,
        ..LiquiditySettings::default()
    })
}

/// True when an order asking each member for `bond_sat` may be taken on under `settings`.
pub fn allowed(settings: &LiquiditySettings, bond_sat: u64) -> bool {
    bond_sat == 0 || (settings.bonds && bond_sat <= settings.max_bond_sat)
}

/// Chains on which this instance may take bonds while the bond code awaits its owner's read.
const BOND_TEST_NETWORKS: [&str; 4] = ["regtest", "testnet", "testnet4", "signet"];

/// Why this instance must not start, if `settings` turn bonds on and the node is on a chain
/// outside [`BOND_TEST_NETWORKS`]. `networks` are the node's chains (LND `GetInfo`); none
/// known (Cashu mode, no node asked) fails closed. Bonds put members' payments on this
/// instance's node, so until the bond code is read they stay on test chains.
pub fn bonds_startup_refusal(settings: &LiquiditySettings, networks: &[String]) -> Option<String> {
    if !settings.bonds {
        return None;
    }
    match networks.first() {
        Some(network) if BOND_TEST_NETWORKS.contains(&network.as_str()) => None,
        Some(network) => Some(format!(
            "[liquidity].bonds = true is refused on {network}: bonds run only on regtest, \
             testnet, testnet4 or signet until the bond code has been read. Set bonds = false."
        )),
        None => Some(
            "[liquidity].bonds = true is refused: the node's chain is not known, and bonds run \
             only on regtest, testnet, testnet4 or signet. Set bonds = false."
                .to_string(),
        ),
    }
}

#[cfg(not(test))]
static NODE: tokio::sync::OnceCell<Arc<dyn LightningBackend>> = tokio::sync::OnceCell::const_new();

/// This instance's node, for bonds. Connected on first use, so an instance that takes no bonds
/// never opens this connection.
#[cfg(not(test))]
pub async fn node() -> Result<Arc<dyn LightningBackend>, MostroError> {
    NODE.get_or_try_init(|| async {
        let ln = crate::config::settings::Settings::get_ln();
        let backend = bipnip_ln::lnd::LndBackend::connect(
            &ln.lnd_grpc_host,
            std::path::Path::new(&ln.lnd_cert_file),
            std::path::Path::new(&ln.lnd_macaroon_file),
        )
        .await
        .map_err(node_err)?;
        Ok::<Arc<dyn LightningBackend>, MostroError>(Arc::new(backend))
    })
    .await
    .cloned()
}

/// In tests, one simulated node shared by every test (each uses its own hashes and node keys).
#[cfg(test)]
pub async fn node() -> Result<Arc<dyn LightningBackend>, MostroError> {
    Ok(testing::shared())
}

fn db_err(e: sqlx::Error) -> MostroError {
    MostroInternalErr(ServiceError::DbAccessError(e.to_string()))
}

fn node_err(e: BackendError) -> MostroError {
    MostroInternalErr(ServiceError::LnNodeError(e.to_string()))
}

fn broken(what: &str) -> MostroError {
    MostroInternalErr(ServiceError::UnexpectedError(what.to_string()))
}

fn refuse(reason: CantDoReason) -> MostroError {
    MostroCantDo(reason)
}

/// A bond row. It has no `Debug`: it carries the hold invoice's preimage.
#[derive(Clone)]
pub struct Bond {
    pub id: Uuid,
    pub payer_identity: String,
    pub amount_sat: u64,
    pub payment_hash: String,
    preimage: String,
    pub state: String,
    /// False while the node call that goes with the state is still owed.
    pub node_done: bool,
    /// Outpoints that were already in the graph when the bond was locked.
    pub graph_before: Vec<String>,
    pub recipient_identity: Option<String>,
    payout_invoice: Option<String>,
    payout_hash: Option<String>,
    payout_expires_at: Option<i64>,
    pub payout_attempts: i64,
    pub created_at: i64,
}

impl Bond {
    /// True once the bond was taken, whatever became of it afterwards.
    pub fn was_taken(&self) -> bool {
        matches!(self.state.as_str(), SLASHED | CLAIMED | PAID | FORFEITED)
    }
}

/// A `SELECT` of every column [`read`] wants, with `$tail` after the table name. The text is
/// fixed at compile time: no query here is built from data.
macro_rules! select_bonds {
    ($tail:literal) => {
        concat!(
            "SELECT id, payer_identity, amount_sat, payment_hash, preimage, state, node_done, \
             graph_before, recipient_identity, payout_invoice, payout_hash, payout_expires_at, \
             payout_attempts, created_at FROM liquidity_bonds ",
            $tail
        )
    };
}

fn read(row: &sqlx::sqlite::SqliteRow) -> Result<Bond, MostroError> {
    let id: String = row.try_get("id").map_err(db_err)?;
    let amount: i64 = row.try_get("amount_sat").map_err(db_err)?;
    let node_done: i64 = row.try_get("node_done").map_err(db_err)?;
    let before: Option<String> = row.try_get("graph_before").map_err(db_err)?;
    let graph_before = match before {
        Some(json) => serde_json::from_str(&json)
            .map_err(|_| broken("a stored graph snapshot does not parse"))?,
        None => Vec::new(),
    };
    Ok(Bond {
        id: Uuid::parse_str(&id).map_err(|_| broken("a bond has a malformed id"))?,
        payer_identity: row.try_get("payer_identity").map_err(db_err)?,
        amount_sat: u64::try_from(amount).map_err(|_| broken("a bond has a negative amount"))?,
        payment_hash: row.try_get("payment_hash").map_err(db_err)?,
        preimage: row.try_get("preimage").map_err(db_err)?,
        state: row.try_get("state").map_err(db_err)?,
        node_done: node_done != 0,
        graph_before,
        recipient_identity: row.try_get("recipient_identity").map_err(db_err)?,
        payout_invoice: row.try_get("payout_invoice").map_err(db_err)?,
        payout_hash: row.try_get("payout_hash").map_err(db_err)?,
        payout_expires_at: row.try_get("payout_expires_at").map_err(db_err)?,
        payout_attempts: row.try_get("payout_attempts").map_err(db_err)?,
        created_at: row.try_get("created_at").map_err(db_err)?,
    })
}

/// The bonds of one order, oldest first.
pub async fn of_order(
    pool: &SqlitePool,
    kind: &str,
    order_id: Uuid,
) -> Result<Vec<Bond>, MostroError> {
    let rows = sqlx::query(select_bonds!(
        "WHERE kind = ? AND order_id = ? ORDER BY created_at, id"
    ))
    .bind(kind)
    .bind(order_id.to_string())
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    rows.iter().map(read).collect()
}

async fn by_id(pool: &SqlitePool, id: Uuid) -> Result<Option<Bond>, MostroError> {
    let row = sqlx::query(select_bonds!("WHERE id = ?"))
        .bind(id.to_string())
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    row.as_ref().map(read).transpose()
}

/// The invoice of `payer`'s bond on an order, if it has one.
async fn invoice_of(
    pool: &SqlitePool,
    kind: &str,
    order_id: Uuid,
    payer: &str,
) -> Result<Option<String>, MostroError> {
    let row = sqlx::query(
        "SELECT invoice FROM liquidity_bonds \
         WHERE kind = ? AND order_id = ? AND payer_identity = ?",
    )
    .bind(kind)
    .bind(order_id.to_string())
    .bind(payer)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    row.map(|row| row.try_get("invoice").map_err(db_err))
        .transpose()
}

/// A fresh preimage and its payment hash, both in hex. The generator does not outlive the call.
fn new_secret() -> (String, String) {
    use bitcoin::hex::DisplayHex;
    use rand::RngCore;
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    let hash = sha256::Hash::hash(&preimage);
    (preimage.to_lower_hex_string(), hash.to_string())
}

/// What a new bond is for.
pub struct Request<'a> {
    pub kind: &'a str,
    pub order_id: Uuid,
    pub payer_identity: &'a str,
    pub payer_trade_pubkey: &'a str,
    pub amount_sat: u64,
    /// Final CLTV delta of the hold invoice: how long the payment can stay locked, in blocks.
    pub cltv_delta: u32,
    /// Shown to the payer; no secrets.
    pub description: &'a str,
}

/// Makes `payer`'s bond on an order: a hold invoice on this node for a preimage only this
/// instance knows. Returns the invoice. A payer has one bond per order: asked again, this
/// returns the invoice it already has.
pub async fn request(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    req: &Request<'_>,
    now: u64,
) -> Result<String, MostroError> {
    if let Some(invoice) = invoice_of(pool, req.kind, req.order_id, req.payer_identity).await? {
        return Ok(invoice);
    }
    let amount_msat = req
        .amount_sat
        .checked_mul(1_000)
        .ok_or_else(|| broken("a bond amount overflows"))?;
    let amount = i64::try_from(req.amount_sat).map_err(|_| broken("a bond amount overflows"))?;
    let (preimage, payment_hash) = new_secret();
    let invoice = node
        .add_hold_invoice(&HoldInvoiceRequest {
            payment_hash: payment_hash.clone(),
            amount_msat,
            expiry_secs: BOND_PAY_WINDOW_SECS as u32,
            cltv_delta: req.cltv_delta,
            description: req.description.to_string(),
        })
        .await
        .map_err(node_err)?;
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO liquidity_bonds \
         (id, kind, order_id, payer_identity, payer_trade_pubkey, amount_sat, payment_hash, \
          preimage, invoice, state, node_done, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(req.kind)
    .bind(req.order_id.to_string())
    .bind(req.payer_identity)
    .bind(req.payer_trade_pubkey)
    .bind(amount)
    .bind(&payment_hash)
    .bind(&preimage)
    .bind(&invoice)
    .bind(REQUESTED)
    .bind(now as i64)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if inserted.rows_affected() == 1 {
        return Ok(invoice);
    }
    // Another task made this payer's bond first. Ours was never sent to anyone: drop it.
    if let Err(e) = node.cancel_hold_invoice(&payment_hash).await {
        tracing::warn!("liquidity bond: a spare hold invoice was not cancelled ({e})");
    }
    invoice_of(pool, req.kind, req.order_id, req.payer_identity)
        .await?
        .ok_or_else(|| broken("a bond vanished while it was being made"))
}

/// Asks the node where the bonds of an order stand and returns them. A paid `requested` bond
/// becomes `locked`. A bond whose invoice the node shows as cancelled (it expired unpaid, or the
/// locked payment ran into its timeout) becomes `released`: the money is back with the payer.
pub async fn refresh(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    kind: &str,
    order_id: Uuid,
) -> Result<Vec<Bond>, MostroError> {
    for bond in of_order(pool, kind, order_id).await? {
        if bond.state != REQUESTED && bond.state != LOCKED {
            continue;
        }
        let seen = node
            .hold_invoice_state(&bond.payment_hash)
            .await
            .map_err(node_err)?;
        match seen {
            HoldState::Accepted if bond.state == REQUESTED => {
                sqlx::query("UPDATE liquidity_bonds SET state = ? WHERE id = ? AND state = ?")
                    .bind(LOCKED)
                    .bind(bond.id.to_string())
                    .bind(REQUESTED)
                    .execute(pool)
                    .await
                    .map_err(db_err)?;
            }
            HoldState::Canceled => {
                sqlx::query(
                    "UPDATE liquidity_bonds SET state = ?, node_done = 1 \
                     WHERE id = ? AND state IN (?, ?)",
                )
                .bind(RELEASED)
                .bind(bond.id.to_string())
                .bind(REQUESTED)
                .bind(LOCKED)
                .execute(pool)
                .await
                .map_err(db_err)?;
            }
            _ => {}
        }
    }
    of_order(pool, kind, order_id).await
}

/// Records the announced channels that already exist between the payer's node and the node it
/// must open to. Written once, when the bond is locked and before anything is opened.
pub async fn note_graph_before(
    pool: &SqlitePool,
    id: Uuid,
    outpoints: &[String],
) -> Result<(), MostroError> {
    let json = serde_json::to_string(outpoints)
        .map_err(|_| MostroInternalErr(ServiceError::MessageSerializationError))?;
    sqlx::query(
        "UPDATE liquidity_bonds SET graph_before = ? WHERE id = ? AND graph_before IS NULL",
    )
    .bind(json)
    .bind(id.to_string())
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Outpoints of the announced channels of exactly `capacity_sat` between nodes `a` and `b`, as
/// this instance's node sees the graph.
pub async fn channels_between(
    node: &dyn LightningBackend,
    a: &str,
    b: &str,
    capacity_sat: u64,
) -> Result<Vec<String>, MostroError> {
    let channels = node.graph_channels(a).await.map_err(node_err)?;
    Ok(channels
        .into_iter()
        .filter(|channel| channel.peer == b && channel.capacity_sat == capacity_sat)
        .map(|channel| channel.funding_outpoint)
        .collect())
}

/// Lets a bond go: the row first, then the node. Does nothing for a bond that is not
/// `requested` or `locked`. A node that cannot be reached leaves the cancel to the housekeeping
/// pass; only a database error is returned.
pub async fn release(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    id: Uuid,
) -> Result<(), MostroError> {
    let moved = sqlx::query(
        "UPDATE liquidity_bonds SET state = ?, node_done = 0 WHERE id = ? AND state IN (?, ?)",
    )
    .bind(RELEASED)
    .bind(id.to_string())
    .bind(REQUESTED)
    .bind(LOCKED)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if moved.rows_affected() != 1 {
        return Ok(());
    }
    let bond = by_id(pool, id)
        .await?
        .ok_or_else(|| broken("a bond vanished while it was released"))?;
    finish_release(pool, node, &bond).await
}

/// Lets go every bond of an order that is still `requested` or `locked`.
pub async fn release_all(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    kind: &str,
    order_id: Uuid,
) -> Result<(), MostroError> {
    for bond in of_order(pool, kind, order_id).await? {
        release(pool, node, bond.id).await?;
    }
    Ok(())
}

/// The node half of a release: cancel the hold invoice, then mark the row done.
async fn finish_release(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    bond: &Bond,
) -> Result<(), MostroError> {
    let cancelled = match node.cancel_hold_invoice(&bond.payment_hash).await {
        Ok(()) => true,
        // Refused: fine if the invoice is already cancelled.
        Err(BackendError::Rejected(_)) => matches!(
            node.hold_invoice_state(&bond.payment_hash).await,
            Ok(HoldState::Canceled)
        ),
        Err(_) => false,
    };
    if !cancelled {
        tracing::warn!(
            "liquidity bond {}: not cancelled on the node yet; housekeeping retries",
            bond.id
        );
        return Ok(());
    }
    sqlx::query("UPDATE liquidity_bonds SET node_done = 1 WHERE id = ? AND state = ?")
        .bind(bond.id.to_string())
        .bind(RELEASED)
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// Takes a locked bond and records who it is owed to: the row first, then the node settles the
/// hold invoice. Returns false, and changes nothing, for a bond that is not `locked`. A node
/// that cannot be reached leaves the settle to the housekeeping pass.
pub async fn slash(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    id: Uuid,
    recipient_identity: &str,
    recipient_trade_pubkey: &str,
    now: u64,
) -> Result<bool, MostroError> {
    let moved = sqlx::query(
        "UPDATE liquidity_bonds SET state = ?, node_done = 0, recipient_identity = ?, \
         recipient_trade_pubkey = ?, slashed_at = ? WHERE id = ? AND state = ?",
    )
    .bind(SLASHED)
    .bind(recipient_identity)
    .bind(recipient_trade_pubkey)
    .bind(now as i64)
    .bind(id.to_string())
    .bind(LOCKED)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if moved.rows_affected() != 1 {
        return Ok(false);
    }
    let bond = by_id(pool, id)
        .await?
        .ok_or_else(|| broken("a bond vanished while it was taken"))?;
    finish_slash(pool, node, &bond).await?;
    Ok(true)
}

/// The node half of taking a bond: settle the hold invoice, then mark the row done. If the
/// locked payment already ran into its timeout there is nothing to settle: the money is back
/// with the payer, so the bond ends as `released` and nobody is owed anything.
async fn finish_slash(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    bond: &Bond,
) -> Result<(), MostroError> {
    let seen = match node.settle_hold_invoice(&bond.preimage).await {
        Ok(()) => Some(HoldState::Settled),
        Err(BackendError::Rejected(_)) => node.hold_invoice_state(&bond.payment_hash).await.ok(),
        Err(_) => None,
    };
    let (to, what) = match seen {
        Some(HoldState::Settled) => (SLASHED, "settled"),
        Some(HoldState::Canceled) => (RELEASED, "timed out before it could be settled"),
        _ => {
            tracing::warn!(
                "liquidity bond {}: not settled on the node yet; housekeeping retries",
                bond.id
            );
            return Ok(());
        }
    };
    tracing::info!("liquidity bond {}: {what}", bond.id);
    sqlx::query(
        "UPDATE liquidity_bonds SET state = ?, node_done = 1 \
         WHERE id = ? AND state = ? AND node_done = 0",
    )
    .bind(to)
    .bind(bond.id.to_string())
    .bind(SLASHED)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// The member a bond is owed to sends its invoice. Checked: `claimant` is the recorded
/// recipient of a taken bond on this order; the bond is settled on the node and no payout is
/// under way; the invoice is payable by this node, asks for exactly the payout amount and stays
/// valid long enough to be paid. The payout itself is made by the housekeeping pass.
pub async fn claim(
    pool: &SqlitePool,
    kind: &str,
    order_id: Uuid,
    claimant: &str,
    invoice: &str,
    now: u64,
) -> Result<(), MostroError> {
    let bonds = of_order(pool, kind, order_id).await?;
    let bond = bonds
        .iter()
        .find(|bond| bond.was_taken() && bond.recipient_identity.as_deref() == Some(claimant))
        .ok_or(refuse(CantDoReason::IsNotYourOrder))?;
    if bond.state != SLASHED || !bond.node_done || bond.payout_attempts >= MAX_PAYOUT_ATTEMPTS {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    let parsed = decode_invoice(invoice).map_err(|_| refuse(CantDoReason::InvalidInvoice))?;
    validate_payout_invoice(&parsed).map_err(|_| refuse(CantDoReason::InvalidInvoice))?;
    let owed_msat = payout_sat(bond.amount_sat)
        .checked_mul(1_000)
        .ok_or_else(|| broken("a bond payout overflows"))?;
    if parsed.amount_milli_satoshis() != Some(owed_msat) {
        return Err(refuse(CantDoReason::InvalidAmount));
    }
    let expires_at = parsed
        .duration_since_epoch()
        .as_secs()
        .saturating_add(parsed.expiry_time().as_secs());
    if expires_at < now.saturating_add(MIN_CLAIM_INVOICE_LIFE_SECS) {
        return Err(refuse(CantDoReason::InvalidInvoice));
    }
    let moved = sqlx::query(
        "UPDATE liquidity_bonds SET state = ?, payout_invoice = ?, payout_hash = ?, \
         payout_expires_at = ?, payout_attempts = payout_attempts + 1 \
         WHERE id = ? AND state = ? AND node_done = 1",
    )
    .bind(CLAIMED)
    .bind(invoice)
    .bind(parsed.payment_hash().to_string())
    .bind(i64::try_from(expires_at).unwrap_or(i64::MAX))
    .bind(bond.id.to_string())
    .bind(SLASHED)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if moved.rows_affected() != 1 {
        return Err(refuse(CantDoReason::NotAllowedByStatus));
    }
    Ok(())
}

/// Puts a claimed bond back to `slashed`, so its recipient can send another invoice.
async fn unclaim(pool: &SqlitePool, id: Uuid) -> Result<(), MostroError> {
    sqlx::query(
        "UPDATE liquidity_bonds SET state = ?, payout_invoice = NULL, payout_hash = NULL, \
         payout_expires_at = NULL WHERE id = ? AND state = ?",
    )
    .bind(SLASHED)
    .bind(id.to_string())
    .bind(CLAIMED)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// One step of a payout. The node is asked about the invoice's payment first, and a payment is
/// sent only when the node has no record of one. `paid` follows a payment the node reports as
/// succeeded; a failed one puts the bond back to `slashed`; anything unclear waits.
async fn payout_step(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    bond: &Bond,
    now: u64,
) -> Result<(), MostroError> {
    let (Some(invoice), Some(hash)) = (&bond.payout_invoice, &bond.payout_hash) else {
        return unclaim(pool, bond.id).await;
    };
    let known = match node.payment_state(hash).await {
        Ok(state) => Some(state),
        // Refused: the node has no payment for this hash.
        Err(BackendError::Rejected(_)) => None,
        Err(e) => {
            tracing::warn!("liquidity bond {}: payout not checked ({e})", bond.id);
            return Ok(());
        }
    };
    let state = match known {
        Some(state) => state,
        None => {
            if bond.payout_expires_at.is_some_and(|at| at <= now as i64) {
                return unclaim(pool, bond.id).await;
            }
            let max_fee_msat = routing_reserve_sat(bond.amount_sat).saturating_mul(1_000);
            match node
                .pay_invoice(invoice, max_fee_msat, PAYOUT_WAIT_SECS)
                .await
            {
                Ok(state) => state,
                // Refused before anything was sent.
                Err(BackendError::Rejected(reason)) => PaymentState::Failed { reason },
                Err(e) => {
                    tracing::warn!("liquidity bond {}: payout not sent ({e})", bond.id);
                    return Ok(());
                }
            }
        }
    };
    match state {
        PaymentState::Succeeded { .. } => {
            sqlx::query("UPDATE liquidity_bonds SET state = ? WHERE id = ? AND state = ?")
                .bind(PAID)
                .bind(bond.id.to_string())
                .bind(CLAIMED)
                .execute(pool)
                .await
                .map_err(db_err)?;
            tracing::info!("liquidity bond {}: paid on to its recipient", bond.id);
            Ok(())
        }
        PaymentState::Failed { reason } => {
            tracing::warn!("liquidity bond {}: payout failed ({reason})", bond.id);
            unclaim(pool, bond.id).await
        }
        PaymentState::InFlight => Ok(()),
    }
}

/// Bonds whose node call (cancel or settle) is still owed.
async fn owing_a_node_call(pool: &SqlitePool) -> Result<Vec<Bond>, MostroError> {
    let rows = sqlx::query(select_bonds!(
        "WHERE node_done = 0 AND state IN ('released', 'slashed') ORDER BY created_at"
    ))
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    rows.iter().map(read).collect()
}

/// Bonds with a payout under way.
async fn being_paid_out(pool: &SqlitePool) -> Result<Vec<Bond>, MostroError> {
    let rows = sqlx::query(select_bonds!("WHERE state = 'claimed' ORDER BY created_at"))
        .fetch_all(pool)
        .await
        .map_err(db_err)?;
    rows.iter().map(read).collect()
}

/// True when any bond still needs the node: one not yet ended, a node call still owed, or a
/// payout under way. An instance without such bonds never connects for them.
pub async fn any_open(pool: &SqlitePool) -> Result<bool, MostroError> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM liquidity_bonds \
         WHERE state IN ('requested', 'locked', 'claimed') OR node_done = 0",
    )
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    let n: i64 = row.try_get("n").map_err(db_err)?;
    Ok(n > 0)
}

/// One housekeeping pass over all bonds at `now`:
///
/// 1. node calls still owed (a cancel for a released bond, a settle for a taken one) are
///    repeated;
/// 2. payouts under way are moved on;
/// 3. taken bonds nobody claimed in time are forfeited.
pub async fn housekeeping(
    pool: &SqlitePool,
    node: &dyn LightningBackend,
    now: u64,
) -> Result<(), MostroError> {
    for bond in owing_a_node_call(pool).await? {
        if bond.state == RELEASED {
            finish_release(pool, node, &bond).await?;
        } else {
            finish_slash(pool, node, &bond).await?;
        }
    }
    for bond in being_paid_out(pool).await? {
        payout_step(pool, node, &bond, now).await?;
    }
    forfeit_unclaimed(pool, now).await
}

/// Forfeits taken bonds whose claim window has passed. Needs no node.
pub async fn forfeit_unclaimed(pool: &SqlitePool, now: u64) -> Result<(), MostroError> {
    sqlx::query(
        "UPDATE liquidity_bonds SET state = ? \
         WHERE state = ? AND node_done = 1 AND slashed_at + ? <= ?",
    )
    .bind(FORFEITED)
    .bind(SLASHED)
    .bind(BOND_CLAIM_WINDOW_SECS as i64)
    .bind(now as i64)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// This instance's node binding: the node signs for the instance's Nostr key (kind 31735), so a
/// member can check that a bond invoice pays the instance's own node before paying it.
pub async fn node_binding_event(
    node: &dyn LightningBackend,
    keys: &Keys,
    now: u64,
) -> Result<Event, MostroError> {
    let info = node.node_info().await.map_err(node_err)?;
    let network = Network::from_str(&info.network)
        .map_err(|_| broken("the node is on a network bipnip does not know"))?;
    let node_pubkey = secp256k1::PublicKey::from_str(&info.node_pubkey)
        .map_err(|_| broken("the node reported a malformed public key"))?;
    let statement = Statement::new(
        BindingAction::Bind,
        network,
        &keys.public_key().to_hex(),
        node_pubkey,
        now,
    )
    .map_err(|_| broken("the instance's node binding could not be built"))?;
    let node_signature = node
        .sign_message(statement.text().as_bytes())
        .await
        .map_err(node_err)?;
    let signed = SignedStatement {
        statement,
        node_signature,
    };
    // The node must have signed with the key it reported.
    signed
        .verify()
        .map_err(|_| broken("the node's signature does not verify"))?;
    let event = signed
        .to_event_builder()
        .finalize(keys)
        .map_err(|e| MostroInternalErr(ServiceError::NostrError(e.to_string())))?;
    SignedStatement::from_event(&event)
        .map_err(|_| broken("the instance's node binding does not verify"))?;
    Ok(event)
}

static BINDING_PUBLISHED: AtomicBool = AtomicBool::new(false);

/// On an instance that takes bonds, publishes its node binding to its relays: once per run,
/// tried again until it has gone out. Does nothing on an instance without bonds.
pub async fn publish_node_binding(ctx: &crate::app::context::AppContext) {
    if !settings().bonds || BINDING_PUBLISHED.load(Ordering::Relaxed) {
        return;
    }
    let published = async {
        let node = node().await?;
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        let event = node_binding_event(&*node, ctx.keys(), now).await?;
        crate::publish::send_event_first_ack(ctx.nostr_client(), &event, |_| {}).await
    };
    match published.await {
        Ok(()) => {
            BINDING_PUBLISHED.store(true, Ordering::Relaxed);
            tracing::info!("liquidity bonds: this instance's node binding is published");
        }
        Err::<(), MostroError>(e) => {
            tracing::warn!("liquidity bonds: node binding not published yet ({e})");
        }
    }
}

/// A simulated node for tests, here and in `app::ring`.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use async_trait::async_trait;
    use bipnip_ln::{ChannelView, GraphChannel, NodeInfo, OpenRequest};
    use mostro_core::node_binding::sign_ln_message;
    use secp256k1::{Secp256k1, SecretKey};
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};

    #[derive(Default)]
    struct Inner {
        holds: HashMap<String, HoldState>,
        payments: HashMap<String, PaymentState>,
        /// Every payment sent: (invoice, fee limit in msat).
        sent: Vec<(String, u64)>,
        graph: HashMap<String, Vec<GraphChannel>>,
        down: bool,
        pay_outcome: Option<PaymentState>,
    }

    pub(crate) struct MockNode {
        key: SecretKey,
        inner: Mutex<Inner>,
    }

    static SHARED: LazyLock<Arc<MockNode>> = LazyLock::new(MockNode::new);

    /// The node every handler-level test shares.
    pub(crate) fn shared() -> Arc<MockNode> {
        SHARED.clone()
    }

    fn down() -> BackendError {
        BackendError::Unavailable("the simulated node is down".into())
    }

    impl MockNode {
        pub(crate) fn new() -> Arc<Self> {
            let key = SecretKey::from_slice(&Keys::generate().secret_key().to_secret_bytes())
                .expect("a key");
            Arc::new(MockNode {
                key,
                inner: Mutex::new(Inner::default()),
            })
        }

        pub(crate) fn pubkey(&self) -> String {
            secp256k1::PublicKey::from_secret_key(&Secp256k1::signing_only(), &self.key).to_string()
        }

        /// The payer pays a hold invoice: it is locked.
        pub(crate) fn pay(&self, hash: &str) {
            let mut inner = self.inner.lock().expect("node");
            let state = inner.holds.get_mut(hash).expect("a hold invoice");
            assert_eq!(*state, HoldState::Open, "paid twice");
            *state = HoldState::Accepted;
        }

        /// The node lets a hold invoice go by itself: it expired, or its payment timed out.
        pub(crate) fn time_out(&self, hash: &str) {
            let mut inner = self.inner.lock().expect("node");
            inner.holds.insert(hash.to_string(), HoldState::Canceled);
        }

        pub(crate) fn hold(&self, hash: &str) -> Option<HoldState> {
            self.inner.lock().expect("node").holds.get(hash).copied()
        }

        pub(crate) fn set_down(&self, down: bool) {
            self.inner.lock().expect("node").down = down;
        }

        /// What the next payments end as; `None` means they succeed.
        pub(crate) fn set_pay_outcome(&self, outcome: Option<PaymentState>) {
            self.inner.lock().expect("node").pay_outcome = outcome;
        }

        /// Changes what the node reports for a payment already sent.
        pub(crate) fn set_payment(&self, hash: &str, state: PaymentState) {
            let mut inner = self.inner.lock().expect("node");
            inner.payments.insert(hash.to_string(), state);
        }

        pub(crate) fn sent(&self) -> Vec<(String, u64)> {
            self.inner.lock().expect("node").sent.clone()
        }

        /// An announced channel between two nodes, seen from both.
        pub(crate) fn announce(&self, a: &str, b: &str, capacity_sat: u64, outpoint: &str) {
            let mut inner = self.inner.lock().expect("node");
            for (from, to) in [(a, b), (b, a)] {
                inner
                    .graph
                    .entry(from.to_string())
                    .or_default()
                    .push(GraphChannel {
                        peer: to.to_string(),
                        capacity_sat,
                        funding_outpoint: outpoint.to_string(),
                    });
            }
        }
    }

    fn unsupported<T>() -> Result<T, BackendError> {
        Err(BackendError::Unsupported("not simulated"))
    }

    #[async_trait]
    impl LightningBackend for MockNode {
        async fn node_info(&self) -> Result<NodeInfo, BackendError> {
            Ok(NodeInfo {
                node_pubkey: self.pubkey(),
                network: "regtest".into(),
                block_height: 100,
                synced: true,
            })
        }

        async fn sign_message(&self, msg: &[u8]) -> Result<String, BackendError> {
            Ok(sign_ln_message(msg, &self.key))
        }

        async fn add_hold_invoice(&self, req: &HoldInvoiceRequest) -> Result<String, BackendError> {
            let mut inner = self.inner.lock().expect("node");
            if inner.down {
                return Err(down());
            }
            inner
                .holds
                .insert(req.payment_hash.clone(), HoldState::Open);
            Ok(format!("lnbcrt1{}", req.payment_hash))
        }

        async fn hold_invoice_state(&self, payment_hash: &str) -> Result<HoldState, BackendError> {
            let inner = self.inner.lock().expect("node");
            if inner.down {
                return Err(down());
            }
            inner
                .holds
                .get(payment_hash)
                .copied()
                .ok_or(BackendError::Rejected("no such invoice".into()))
        }

        async fn settle_hold_invoice(&self, preimage: &str) -> Result<(), BackendError> {
            use bitcoin::hex::FromHex;
            let mut inner = self.inner.lock().expect("node");
            if inner.down {
                return Err(down());
            }
            let bytes = <[u8; 32]>::from_hex(preimage)
                .map_err(|_| BackendError::Rejected("preimage".into()))?;
            let hash = sha256::Hash::hash(&bytes).to_string();
            match inner.holds.get_mut(&hash) {
                Some(state @ HoldState::Accepted) => {
                    *state = HoldState::Settled;
                    Ok(())
                }
                Some(HoldState::Settled) => Ok(()),
                _ => Err(BackendError::Rejected("nothing to settle".into())),
            }
        }

        async fn cancel_hold_invoice(&self, payment_hash: &str) -> Result<(), BackendError> {
            let mut inner = self.inner.lock().expect("node");
            if inner.down {
                return Err(down());
            }
            match inner.holds.get_mut(payment_hash) {
                Some(HoldState::Settled) | None => {
                    Err(BackendError::Rejected("cannot cancel".into()))
                }
                Some(state) => {
                    *state = HoldState::Canceled;
                    Ok(())
                }
            }
        }

        async fn pay_invoice(
            &self,
            bolt11: &str,
            max_fee_msat: u64,
            _wait_secs: u32,
        ) -> Result<PaymentState, BackendError> {
            let mut inner = self.inner.lock().expect("node");
            if inner.down {
                return Err(down());
            }
            let hash = decode_invoice(bolt11)
                .map_err(|_| BackendError::Rejected("invoice".into()))?
                .payment_hash()
                .to_string();
            if matches!(
                inner.payments.get(&hash),
                Some(PaymentState::InFlight | PaymentState::Succeeded { .. })
            ) {
                return Err(BackendError::Rejected("already paid or in flight".into()));
            }
            inner.sent.push((bolt11.to_string(), max_fee_msat));
            let outcome = inner
                .pay_outcome
                .clone()
                .unwrap_or(PaymentState::Succeeded {
                    preimage: "00".repeat(32),
                });
            inner.payments.insert(hash, outcome.clone());
            Ok(outcome)
        }

        async fn payment_state(&self, payment_hash: &str) -> Result<PaymentState, BackendError> {
            let inner = self.inner.lock().expect("node");
            if inner.down {
                return Err(down());
            }
            inner
                .payments
                .get(payment_hash)
                .cloned()
                .ok_or(BackendError::Rejected("no such payment".into()))
        }

        async fn add_invoice(&self, _: u64, _: u32, _: &str) -> Result<String, BackendError> {
            unsupported()
        }

        async fn connect(&self, _: &str, _: &str) -> Result<(), BackendError> {
            unsupported()
        }

        async fn open_channel(&self, _: &OpenRequest) -> Result<String, BackendError> {
            unsupported()
        }

        async fn channels_with(&self, _: &str) -> Result<Vec<ChannelView>, BackendError> {
            unsupported()
        }

        async fn graph_node(&self, _: &str) -> Result<Option<(u32, u64)>, BackendError> {
            unsupported()
        }

        async fn graph_channels(&self, node: &str) -> Result<Vec<GraphChannel>, BackendError> {
            let inner = self.inner.lock().expect("node");
            if inner.down {
                return Err(down());
            }
            Ok(inner.graph.get(node).cloned().unwrap_or_default())
        }
    }

    /// A real regtest invoice for `amount_msat`, valid for `expiry_secs` from now, with a hash
    /// of its own. Returns the invoice and its payment hash.
    pub(crate) fn invoice(amount_msat: u64, expiry_secs: u64) -> (String, String) {
        use bitcoin::secp256k1::{Secp256k1 as BitcoinSecp, SecretKey as BitcoinKey};
        use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
        use std::time::Duration;

        let (_, hash) = new_secret();
        let payment_hash = sha256::Hash::from_str(&hash).expect("a hash");
        let secp = BitcoinSecp::new();
        let key = BitcoinKey::from_slice(&[0x42; 32]).expect("a key");
        let invoice = InvoiceBuilder::new(Currency::Regtest)
            .description("bond claim".into())
            .payment_hash(payment_hash)
            .payment_secret(PaymentSecret([7u8; 32]))
            .current_timestamp()
            .min_final_cltv_expiry_delta(80)
            .expiry_time(Duration::from_secs(expiry_secs))
            .amount_milli_satoshis(amount_msat)
            .build_signed(|digest| secp.sign_ecdsa_recoverable(digest, &key))
            .expect("an invoice")
            .to_string();
        (invoice, hash)
    }

    /// An empty database with every migration applied.
    pub(crate) async fn pool() -> SqlitePool {
        let _ = crate::config::MOSTRO_CONFIG.set(crate::app::context::test_utils::test_settings());
        // One connection: an in-memory SQLite database is per connection.
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("a database");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations");
        pool
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{invoice, pool, MockNode};
    use super::*;

    /// One fixed "now" for the whole run: the real time, because claim invoices are real ones.
    static START: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock")
            .as_secs()
    });

    fn now() -> u64 {
        *START
    }
    const BOND: u64 = 50_000;

    fn key() -> String {
        Keys::generate().public_key().to_hex()
    }

    fn cant_do(result: Result<(), MostroError>) -> CantDoReason {
        match result {
            Err(MostroCantDo(reason)) => reason,
            Err(other) => panic!("expected a cant-do, got {other:?}"),
            Ok(()) => panic!("expected a cant-do, got Ok"),
        }
    }

    /// One order with one bond of `payer`, as the handlers would make it.
    struct Case {
        pool: SqlitePool,
        node: Arc<MockNode>,
        order: Uuid,
        payer: String,
        recipient: String,
    }

    impl Case {
        async fn new() -> Self {
            let case = Case {
                pool: pool().await,
                node: MockNode::new(),
                order: Uuid::new_v4(),
                payer: key(),
                recipient: key(),
            };
            case.request().await;
            case
        }

        async fn request(&self) -> String {
            let trade = key();
            let req = Request {
                kind: RING,
                order_id: self.order,
                payer_identity: &self.payer,
                payer_trade_pubkey: &trade,
                amount_sat: BOND,
                cltv_delta: 300,
                description: "test bond",
            };
            request(&self.pool, &*self.node, &req, now())
                .await
                .expect("a bond")
        }

        async fn bond(&self) -> Bond {
            let mut bonds = of_order(&self.pool, RING, self.order).await.expect("bonds");
            assert_eq!(bonds.len(), 1);
            bonds.remove(0)
        }

        async fn state(&self) -> (String, bool) {
            let bond = self.bond().await;
            (bond.state, bond.node_done)
        }

        /// The payer pays and the instance sees it.
        async fn lock(&self) -> Bond {
            self.node.pay(&self.bond().await.payment_hash);
            refresh(&self.pool, &*self.node, RING, self.order)
                .await
                .expect("refresh");
            let bond = self.bond().await;
            assert_eq!(bond.state, LOCKED);
            bond
        }

        async fn slash(&self) -> Bond {
            let bond = self.lock().await;
            let trade = key();
            let taken = slash(
                &self.pool,
                &*self.node,
                bond.id,
                &self.recipient,
                &trade,
                now(),
            )
            .await
            .expect("slash");
            assert!(taken);
            self.bond().await
        }

        async fn claim(&self, who: &str, invoice: &str) -> Result<(), MostroError> {
            claim(&self.pool, RING, self.order, who, invoice, now()).await
        }

        async fn pass(&self, now: u64) {
            housekeeping(&self.pool, &*self.node, now)
                .await
                .expect("housekeeping");
        }
    }

    fn owed_msat() -> u64 {
        payout_sat(BOND) * 1_000
    }

    #[tokio::test]
    async fn a_payer_has_one_bond_per_order_and_the_preimage_stays_here() {
        let case = Case::new().await;
        let bond = case.bond().await;
        assert_eq!(bond.state, REQUESTED);
        assert_eq!(bond.amount_sat, BOND);
        assert_eq!(case.node.hold(&bond.payment_hash), Some(HoldState::Open));
        // The invoice names the hash, never the preimage.
        let first = case.request().await;
        assert!(first.contains(&bond.payment_hash));
        assert!(!first.contains(&bond.preimage));
        // Asked again, the same invoice comes back and no second one exists.
        assert_eq!(case.request().await, first);
        assert_eq!(case.bond().await.payment_hash, bond.payment_hash);
    }

    #[tokio::test]
    async fn a_node_that_is_down_makes_no_bond() {
        let pool = pool().await;
        let node = MockNode::new();
        node.set_down(true);
        let (payer, trade) = (key(), key());
        let order = Uuid::new_v4();
        let req = Request {
            kind: RING,
            order_id: order,
            payer_identity: &payer,
            payer_trade_pubkey: &trade,
            amount_sat: BOND,
            cltv_delta: 300,
            description: "test bond",
        };
        assert!(request(&pool, &*node, &req, now()).await.is_err());
        assert!(of_order(&pool, RING, order).await.unwrap().is_empty());
        assert!(!any_open(&pool).await.unwrap());
    }

    #[tokio::test]
    async fn a_paid_bond_is_locked_and_an_expired_one_is_released() {
        let case = Case::new().await;
        // Not paid yet: nothing changes.
        refresh(&case.pool, &*case.node, RING, case.order)
            .await
            .unwrap();
        assert_eq!(case.state().await.0, REQUESTED);
        assert!(any_open(&case.pool).await.unwrap());
        case.lock().await;

        let unpaid = Case::new().await;
        unpaid.node.time_out(&unpaid.bond().await.payment_hash);
        refresh(&unpaid.pool, &*unpaid.node, RING, unpaid.order)
            .await
            .unwrap();
        assert_eq!(unpaid.state().await, (RELEASED.to_string(), true));
        assert!(!any_open(&unpaid.pool).await.unwrap());

        // A locked payment that ran into its timeout is back with the payer: released too.
        let timed_out = Case::new().await;
        let bond = timed_out.lock().await;
        timed_out.node.time_out(&bond.payment_hash);
        refresh(&timed_out.pool, &*timed_out.node, RING, timed_out.order)
            .await
            .unwrap();
        assert_eq!(timed_out.state().await, (RELEASED.to_string(), true));

        // While the node is down nothing is decided.
        let blind = Case::new().await;
        blind.node.set_down(true);
        assert!(refresh(&blind.pool, &*blind.node, RING, blind.order)
            .await
            .is_err());
        assert_eq!(blind.state().await.0, REQUESTED);
    }

    #[tokio::test]
    async fn a_release_cancels_the_invoice_and_survives_a_node_that_is_down() {
        let case = Case::new().await;
        let bond = case.lock().await;
        release(&case.pool, &*case.node, bond.id).await.unwrap();
        assert_eq!(case.state().await, (RELEASED.to_string(), true));
        assert_eq!(
            case.node.hold(&bond.payment_hash),
            Some(HoldState::Canceled)
        );
        // Again: nothing happens, and a released bond cannot be taken.
        release(&case.pool, &*case.node, bond.id).await.unwrap();
        let taken = slash(&case.pool, &*case.node, bond.id, &key(), &key(), now())
            .await
            .unwrap();
        assert!(!taken);
        assert_eq!(case.state().await.0, RELEASED);

        // Node down: the row says released, the cancel is owed, and housekeeping makes it.
        let late = Case::new().await;
        let bond = late.lock().await;
        late.node.set_down(true);
        release(&late.pool, &*late.node, bond.id).await.unwrap();
        assert_eq!(late.state().await, (RELEASED.to_string(), false));
        assert!(any_open(&late.pool).await.unwrap());
        late.pass(now()).await;
        assert_eq!(late.state().await, (RELEASED.to_string(), false));
        late.node.set_down(false);
        assert_eq!(
            late.node.hold(&bond.payment_hash),
            Some(HoldState::Accepted)
        );
        late.pass(now()).await;
        assert_eq!(late.state().await, (RELEASED.to_string(), true));
        assert_eq!(
            late.node.hold(&bond.payment_hash),
            Some(HoldState::Canceled)
        );
        assert!(!any_open(&late.pool).await.unwrap());

        // An unpaid bond can be released as well.
        let unpaid = Case::new().await;
        release_all(&unpaid.pool, &*unpaid.node, RING, unpaid.order)
            .await
            .unwrap();
        assert_eq!(unpaid.state().await, (RELEASED.to_string(), true));
    }

    #[tokio::test]
    async fn only_a_locked_bond_is_taken_and_only_once() {
        // Not paid: there is nothing to take.
        let unpaid = Case::new().await;
        let bond = unpaid.bond().await;
        let taken = slash(&unpaid.pool, &*unpaid.node, bond.id, &key(), &key(), now())
            .await
            .unwrap();
        assert!(!taken);
        assert_eq!(unpaid.state().await.0, REQUESTED);
        assert_eq!(unpaid.node.hold(&bond.payment_hash), Some(HoldState::Open));

        let case = Case::new().await;
        let bond = case.slash().await;
        assert_eq!((bond.state.as_str(), bond.node_done), (SLASHED, true));
        assert!(bond.was_taken());
        assert_eq!(bond.recipient_identity.as_deref(), Some(&*case.recipient));
        assert_eq!(case.node.hold(&bond.payment_hash), Some(HoldState::Settled));
        // A second taker gets nothing, and the recipient does not change.
        let again = slash(&case.pool, &*case.node, bond.id, &key(), &key(), now())
            .await
            .unwrap();
        assert!(!again);
        assert_eq!(
            case.bond().await.recipient_identity.as_deref(),
            Some(&*case.recipient)
        );
        // Nor can it be released any more.
        release(&case.pool, &*case.node, bond.id).await.unwrap();
        assert_eq!(case.state().await.0, SLASHED);
        assert_eq!(case.node.hold(&bond.payment_hash), Some(HoldState::Settled));
    }

    #[tokio::test]
    async fn a_settle_that_could_not_reach_the_node_is_repeated() {
        let case = Case::new().await;
        let bond = case.lock().await;
        case.node.set_down(true);
        let taken = slash(
            &case.pool,
            &*case.node,
            bond.id,
            &case.recipient,
            &key(),
            now(),
        )
        .await
        .unwrap();
        assert!(taken);
        assert_eq!(case.state().await, (SLASHED.to_string(), false));
        // Not settled yet: a claim has to wait.
        let (claim_invoice, _) = invoice(owed_msat(), 3_600);
        assert_eq!(
            cant_do(case.claim(&case.recipient, &claim_invoice).await),
            CantDoReason::NotAllowedByStatus
        );
        case.node.set_down(false);
        case.pass(now()).await;
        assert_eq!(case.state().await, (SLASHED.to_string(), true));
        assert_eq!(case.node.hold(&bond.payment_hash), Some(HoldState::Settled));
        case.claim(&case.recipient, &claim_invoice).await.unwrap();
    }

    #[tokio::test]
    async fn a_bond_whose_payment_timed_out_before_the_settle_is_owed_to_nobody() {
        let case = Case::new().await;
        let bond = case.lock().await;
        case.node.set_down(true);
        slash(
            &case.pool,
            &*case.node,
            bond.id,
            &case.recipient,
            &key(),
            now(),
        )
        .await
        .unwrap();
        // The node let the payment go while it could not be reached.
        case.node.time_out(&bond.payment_hash);
        case.node.set_down(false);
        case.pass(now()).await;
        assert_eq!(case.state().await, (RELEASED.to_string(), true));
        let (claim_invoice, _) = invoice(owed_msat(), 3_600);
        assert_eq!(
            cant_do(case.claim(&case.recipient, &claim_invoice).await),
            CantDoReason::IsNotYourOrder
        );
        assert!(case.node.sent().is_empty());
    }

    #[tokio::test]
    async fn a_claim_is_paid_once_to_the_recipient_for_the_exact_amount() {
        let case = Case::new().await;
        let bond = case.slash().await;
        let (good, hash) = invoice(owed_msat(), 3_600);

        // Someone else, even the payer, is refused.
        assert_eq!(
            cant_do(case.claim(&key(), &good).await),
            CantDoReason::IsNotYourOrder
        );
        assert_eq!(
            cant_do(case.claim(&case.payer, &good).await),
            CantDoReason::IsNotYourOrder
        );
        // The whole bond, one satoshi more, one less, no amount: refused.
        for amount in [BOND * 1_000, owed_msat() + 1_000, owed_msat() - 1_000] {
            let (wrong, _) = invoice(amount, 3_600);
            assert_eq!(
                cant_do(case.claim(&case.recipient, &wrong).await),
                CantDoReason::InvalidAmount
            );
        }
        // Not an invoice, and one that expires too soon to be paid.
        assert_eq!(
            cant_do(case.claim(&case.recipient, "lnbcrt1notaninvoice").await),
            CantDoReason::InvalidInvoice
        );
        let (short, _) = invoice(owed_msat(), 60);
        assert_eq!(
            cant_do(case.claim(&case.recipient, &short).await),
            CantDoReason::InvalidInvoice
        );
        assert_eq!(case.state().await.0, SLASHED);
        assert!(case.node.sent().is_empty());

        case.claim(&case.recipient, &good).await.unwrap();
        assert_eq!(case.state().await.0, CLAIMED);
        assert!(any_open(&case.pool).await.unwrap());
        // While a payout is under way no other invoice is taken.
        let (second, _) = invoice(owed_msat(), 3_600);
        assert_eq!(
            cant_do(case.claim(&case.recipient, &second).await),
            CantDoReason::NotAllowedByStatus
        );

        case.pass(now()).await;
        assert_eq!(case.state().await.0, PAID);
        // One payment: that invoice, with the fee capped at the routing reserve.
        assert_eq!(
            case.node.sent(),
            vec![(good.clone(), routing_reserve_sat(BOND) * 1_000)]
        );
        assert!(matches!(
            case.node.payment_state(&hash).await,
            Ok(PaymentState::Succeeded { .. })
        ));
        // More passes and more claims pay nothing more.
        case.pass(now() + 60).await;
        assert_eq!(
            cant_do(case.claim(&case.recipient, &second).await),
            CantDoReason::NotAllowedByStatus
        );
        case.pass(now() + 120).await;
        assert_eq!(case.node.sent().len(), 1);
        assert_eq!(case.bond().await.payout_attempts, 1);
        assert_eq!(case.node.hold(&bond.payment_hash), Some(HoldState::Settled));
        assert!(!any_open(&case.pool).await.unwrap());
    }

    #[tokio::test]
    async fn a_payout_in_flight_is_never_sent_again() {
        let case = Case::new().await;
        case.slash().await;
        let (good, hash) = invoice(owed_msat(), 3_600);
        case.claim(&case.recipient, &good).await.unwrap();
        case.node.set_pay_outcome(Some(PaymentState::InFlight));
        case.pass(now()).await;
        assert_eq!(case.state().await.0, CLAIMED);
        assert_eq!(case.node.sent().len(), 1);
        // Still in flight on later passes, even past the invoice's expiry: nothing is sent and
        // no other invoice is taken.
        case.pass(now() + 60).await;
        case.pass(now() + 7_200).await;
        assert_eq!(case.state().await.0, CLAIMED);
        assert_eq!(case.node.sent().len(), 1);
        let (second, _) = invoice(owed_msat(), 3_600);
        assert_eq!(
            cant_do(case.claim(&case.recipient, &second).await),
            CantDoReason::NotAllowedByStatus
        );
        // The node cannot be asked: nothing is decided.
        case.node.set_down(true);
        case.pass(now() + 7_260).await;
        assert_eq!(case.state().await.0, CLAIMED);
        case.node.set_down(false);
        // It lands.
        case.node.set_payment(
            &hash,
            PaymentState::Succeeded {
                preimage: "11".repeat(32),
            },
        );
        case.pass(now() + 7_320).await;
        assert_eq!(case.state().await.0, PAID);
        assert_eq!(case.node.sent().len(), 1);
    }

    #[tokio::test]
    async fn a_failed_payout_lets_the_recipient_send_another_invoice() {
        let case = Case::new().await;
        case.slash().await;
        let (first, _) = invoice(owed_msat(), 3_600);
        case.claim(&case.recipient, &first).await.unwrap();
        case.node.set_pay_outcome(Some(PaymentState::Failed {
            reason: "no route".into(),
        }));
        case.pass(now()).await;
        assert_eq!(case.state().await.0, SLASHED);
        assert_eq!(case.bond().await.payout_attempts, 1);

        // A payout the node never started, and whose invoice has expired, is dropped too.
        let (second, _) = invoice(owed_msat(), 3_600);
        case.claim(&case.recipient, &second).await.unwrap();
        case.node.set_down(true);
        case.pass(now()).await;
        assert_eq!(case.state().await.0, CLAIMED);
        case.node.set_down(false);
        case.pass(now() + 3_700).await;
        assert_eq!(case.state().await.0, SLASHED);
        assert_eq!(case.node.sent().len(), 1);

        case.node.set_pay_outcome(None);
        let (third, _) = invoice(owed_msat(), 3_600);
        case.claim(&case.recipient, &third).await.unwrap();
        case.pass(now()).await;
        assert_eq!(case.state().await.0, PAID);
        let sent = case.node.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].0, third);
        assert_eq!(case.bond().await.payout_attempts, 3);
    }

    #[tokio::test]
    async fn payouts_stop_after_too_many_attempts() {
        let case = Case::new().await;
        case.slash().await;
        case.node.set_pay_outcome(Some(PaymentState::Failed {
            reason: "no route".into(),
        }));
        for _ in 0..MAX_PAYOUT_ATTEMPTS {
            let (next, _) = invoice(owed_msat(), 3_600);
            case.claim(&case.recipient, &next).await.unwrap();
            case.pass(now()).await;
            assert_eq!(case.state().await.0, SLASHED);
        }
        let (one_more, _) = invoice(owed_msat(), 3_600);
        assert_eq!(
            cant_do(case.claim(&case.recipient, &one_more).await),
            CantDoReason::NotAllowedByStatus
        );
    }

    #[tokio::test]
    async fn an_unclaimed_bond_is_forfeited_after_the_claim_window() {
        let case = Case::new().await;
        case.slash().await;
        case.pass(now() + BOND_CLAIM_WINDOW_SECS - 1).await;
        assert_eq!(case.state().await.0, SLASHED);
        case.pass(now() + BOND_CLAIM_WINDOW_SECS).await;
        assert_eq!(case.state().await.0, FORFEITED);
        assert!(case.bond().await.was_taken());
        let (late, _) = invoice(owed_msat(), 3_600);
        assert_eq!(
            cant_do(case.claim(&case.recipient, &late).await),
            CantDoReason::NotAllowedByStatus
        );
        case.pass(now() + BOND_CLAIM_WINDOW_SECS + 60).await;
        assert!(case.node.sent().is_empty());

        // A payout under way is not cut off by the window.
        let busy = Case::new().await;
        busy.slash().await;
        let (good, _) = invoice(owed_msat(), 3_600);
        busy.claim(&busy.recipient, &good).await.unwrap();
        forfeit_unclaimed(&busy.pool, now() + BOND_CLAIM_WINDOW_SECS + 1)
            .await
            .unwrap();
        assert_eq!(busy.state().await.0, CLAIMED);
    }

    #[tokio::test]
    async fn the_graph_snapshot_is_written_once_and_only_matching_channels_count() {
        let case = Case::new().await;
        let bond = case.lock().await;
        let (a, b, c) = (key(), key(), key());
        case.node.announce(&a, &b, 1_000_000, "aa:0");
        case.node.announce(&a, &b, 2_000_000, "bb:1");
        case.node.announce(&a, &c, 1_000_000, "cc:0");
        let between = channels_between(&*case.node, &a, &b, 1_000_000)
            .await
            .unwrap();
        assert_eq!(between, vec!["aa:0".to_string()]);
        // Seen from the other end too, and nothing for a node the graph does not have.
        assert_eq!(
            channels_between(&*case.node, &b, &a, 1_000_000)
                .await
                .unwrap(),
            between
        );
        assert!(channels_between(&*case.node, &key(), &a, 1_000_000)
            .await
            .unwrap()
            .is_empty());

        note_graph_before(&case.pool, bond.id, &between)
            .await
            .unwrap();
        note_graph_before(&case.pool, bond.id, &["zz:9".to_string()])
            .await
            .unwrap();
        assert_eq!(case.bond().await.graph_before, between);
    }

    #[test]
    fn bonds_are_refused_off_test_chains() {
        let off = LiquiditySettings::default();
        let on = LiquiditySettings {
            bonds: true,
            ..LiquiditySettings::default()
        };
        let chain = |name: &str| vec![name.to_string()];
        for name in ["regtest", "testnet", "testnet4", "signet"] {
            assert_eq!(bonds_startup_refusal(&on, &chain(name)), None, "{name}");
        }
        for name in ["mainnet", "bitcoin", "Mainnet", "", "simnet"] {
            assert!(bonds_startup_refusal(&on, &chain(name)).is_some(), "{name}");
        }
        assert!(bonds_startup_refusal(&on, &[]).is_some());
        // Only the first chain counts, as for dev fees.
        assert!(bonds_startup_refusal(&on, &["mainnet".into(), "regtest".into()]).is_some());
        // Bonds off: nothing is refused anywhere.
        assert_eq!(bonds_startup_refusal(&off, &chain("mainnet")), None);
        assert_eq!(bonds_startup_refusal(&off, &[]), None);
    }

    #[test]
    fn bonds_are_off_unless_the_settings_turn_them_on() {
        let absent = parse_settings("[mostro]\nfee = 0.0\n").unwrap();
        assert_eq!(absent, LiquiditySettings::default());
        assert!(!absent.bonds);
        assert!(allowed(&absent, 0));
        assert!(!allowed(&absent, 1_000));

        let empty = parse_settings("[liquidity]\n").unwrap();
        assert!(!empty.bonds);

        let on = parse_settings("[liquidity]\nbonds = true\nmax_bond_sat = 20000\n").unwrap();
        assert!(on.bonds);
        assert!(allowed(&on, 20_000));
        assert!(!allowed(&on, 20_001));
        assert!(allowed(&on, 0));

        // A misspelt key is an error, not a silent default.
        assert!(parse_settings("[liquidity]\nbond = true\n").is_err());

        // The lease bond window: 48 hours unless set, and never outside a minute to 48 hours.
        assert_eq!(on.lease_bond_window_secs, 172_800);
        let short = parse_settings("[liquidity]\nlease_bond_window_secs = 120\n").unwrap();
        assert_eq!(short.lease_bond_window_secs, 120);
        assert!(parse_settings("[liquidity]\nlease_bond_window_secs = 59\n").is_err());
        assert!(parse_settings("[liquidity]\nlease_bond_window_secs = 172801\n").is_err());
    }

    #[tokio::test]
    async fn the_instance_binding_is_signed_by_its_node_for_its_key() {
        let node = MockNode::new();
        let keys = Keys::generate();
        let event = node_binding_event(&*node, &keys, now()).await.unwrap();
        assert_eq!(event.pubkey, keys.public_key());
        let seen = SignedStatement::from_event(&event).expect("verifies");
        assert_eq!(seen.statement.node_pubkey.to_string(), node.pubkey());
        assert_eq!(seen.statement.network, Network::Regtest);
        assert_eq!(seen.statement.action, BindingAction::Bind);
    }
}
