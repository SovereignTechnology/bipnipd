//! bipnip: what this instance checks about a node before it lists the node's offer or lets the
//! node take a slot or a lease, beyond the binding's own signatures (checked by the caller):
//!
//! 1. the offer's network is this instance's node's network;
//! 2. the node has not revoked the binding it sent, or bound another key since: its newest
//!    statement, among those on the relays and the one sent, still binds the sender's key;
//! 3. a lease seller is in this instance's graph (`[liquidity] require_seller_in_graph`, on by
//!    default); a buyer or a ring member need not be, since a node with no channel yet is who
//!    buys liquidity;
//! 4. the node meets the order's rules in this instance's graph.
//!
//! The checks ask this instance's node and the relays. All of them together get [`VET_TIMEOUT`]:
//! the event loop handles one message at a time, and a slow relay must not stall fiat trades.
//! They fail closed: an answer that does not come in time is the refusal `check_unavailable`,
//! which the sender's agent may try again.

use std::str::FromStr;
use std::time::Duration;

use mostro_core::error::CantDoReason;
use mostro_core::node_binding::{is_bound, Network, SignedStatement};
use mostro_core::rules::Rules;
use nostr_sdk::prelude::Event;
use secp256k1::PublicKey;

use crate::app::liquidity_bond;

/// Time for every check on one node together.
pub const VET_TIMEOUT: Duration = Duration::from_secs(5);

/// A node to check, and what it must meet.
pub struct Candidate<'a> {
    /// The node.
    pub node: PublicKey,
    /// The network its order is on.
    pub network: Network,
    /// The Nostr key (hex) the node's binding must still bind: the sender's identity.
    pub identity: &'a str,
    /// The binding the node's agent sent, as JSON; its signatures were checked by the caller.
    pub binding: &'a str,
    /// The order's rules the node must meet in this instance's graph.
    pub rules: Rules,
    /// True when the node must be in this instance's graph whatever the rules.
    pub must_be_in_graph: bool,
}

/// Runs every check on `candidate` within [`VET_TIMEOUT`]; the refusal to send when one fails.
pub async fn vet(candidate: &Candidate<'_>, now: u64) -> Result<(), CantDoReason> {
    match tokio::time::timeout(VET_TIMEOUT, checks(candidate, now)).await {
        Ok(result) => result,
        Err(_) => Err(CantDoReason::CheckUnavailable),
    }
}

async fn checks(candidate: &Candidate<'_>, now: u64) -> Result<(), CantDoReason> {
    let node = liquidity_bond::node()
        .await
        .map_err(|_| CantDoReason::CheckUnavailable)?;
    let info = node
        .node_info()
        .await
        .map_err(|_| CantDoReason::CheckUnavailable)?;
    if Network::from_str(&info.network).ok() != Some(candidate.network) {
        return Err(CantDoReason::InvalidParameters);
    }
    let sent = serde_json::from_str::<Event>(candidate.binding)
        .ok()
        .and_then(|event| SignedStatement::from_event(&event).ok())
        .ok_or(CantDoReason::NotAuthorized)?;
    let relayed = statements(&candidate.node).await?;
    if !still_bound(candidate, &sent, &relayed, now) {
        return Err(CantDoReason::BindingRevoked);
    }
    if candidate.must_be_in_graph || !candidate.rules.is_none() {
        let graph = node
            .graph_node(&candidate.node.to_string())
            .await
            .map_err(|_| CantDoReason::CheckUnavailable)?;
        if candidate.must_be_in_graph && graph.is_none() {
            return Err(CantDoReason::NodeNotInGraph);
        }
        if !candidate.rules.met_by(graph) {
            return Err(CantDoReason::RulesNotMet);
        }
    }
    Ok(())
}

/// True when the node's newest statement, among those relayed and the one sent, binds the
/// candidate's identity on its network.
fn still_bound(
    candidate: &Candidate<'_>,
    sent: &SignedStatement,
    relayed: &[SignedStatement],
    now: u64,
) -> bool {
    is_bound(
        &candidate.node,
        candidate.identity,
        candidate.network,
        relayed.iter().chain(std::iter::once(sent)),
        now,
    )
}

/// The node's binding statements on the relays, each fully checked; one that does not check is
/// passed over. A relay that does not answer is `check_unavailable`.
#[cfg(not(test))]
async fn statements(node: &PublicKey) -> Result<Vec<SignedStatement>, CantDoReason> {
    use mostro_core::node_binding::KIND_NODE_BINDING;
    use nostr_sdk::prelude::{Filter, Kind};

    let client = crate::util::get_nostr_client().map_err(|_| CantDoReason::CheckUnavailable)?;
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_NODE_BINDING))
        .identifier(node.to_string());
    let events = client
        .fetch_events(filter)
        .timeout(VET_TIMEOUT)
        .await
        .map_err(|_| CantDoReason::CheckUnavailable)?;
    Ok(events
        .iter()
        .filter_map(|event| SignedStatement::from_event(event).ok())
        .collect())
}

/// In tests, the statements a test put on the simulated relays.
#[cfg(test)]
async fn statements(node: &PublicKey) -> Result<Vec<SignedStatement>, CantDoReason> {
    Ok(testing::relayed(node))
}

/// Simulated relays for tests.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::Mutex;

    static RELAYED: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// Puts a binding event (JSON) on the simulated relays.
    pub(crate) fn relay(binding: &str) {
        RELAYED.lock().expect("relays").push(binding.to_string());
    }

    pub(super) fn relayed(node: &PublicKey) -> Vec<SignedStatement> {
        RELAYED
            .lock()
            .expect("relays")
            .iter()
            .filter_map(|json| serde_json::from_str::<Event>(json).ok())
            .filter_map(|event| SignedStatement::from_event(&event).ok())
            .filter(|statement| statement.statement.node_pubkey == *node)
            .collect()
    }
}
