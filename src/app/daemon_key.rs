//! bipnip (upstream MostroP2P/mostro#1102): over Nostr, the daemon's own key is not a solver.
//!
//! An event signed with the node's key reaches the same handlers as a solver's, and those handlers
//! let that key take any dispute (skipping the solver table and the takeover rule), and settle or
//! cancel it without a permission check. The admin RPC needs those branches: it acts as the daemon
//! key by design, once gRPC has authenticated the operator. So the refusal sits where relay events
//! are dispatched ([`refusal`], called by both event loops), and the RPC, which calls the handlers
//! directly, keeps them.
//!
//! Over Nostr an operator works disputes with a solver key added by `admin-add-solver`, which still
//! takes the daemon key, as does cancelling an order nobody has taken yet (draining the book).

use crate::app::context::AppContext;
use crate::util::get_order;
use mostro_core::error::CantDoReason;
use mostro_core::message::{Action, Message};
use mostro_core::order::{Order, Status};
use mostro_core::transport::UnwrappedMessage;
use nostr_sdk::prelude::Keys;

/// Why a relay event is refused before any handler sees it; `None` lets it through.
///
/// Only events that carry the daemon's key, as identity or as trade key, are looked at. Taking a
/// dispute answers `invalid_pubkey`, as for any key that is not a solver; settling, and cancelling
/// anything already taken, answer `not_authorized`.
pub async fn refusal(
    ctx: &AppContext,
    action: &Action,
    msg: &Message,
    event: &UnwrappedMessage,
    my_keys: &Keys,
) -> Option<CantDoReason> {
    let node = my_keys.public_key();
    if event.identity != node && event.sender != node {
        return None;
    }
    match action {
        Action::AdminTakeDispute => Some(CantDoReason::InvalidPubkey),
        Action::AdminSettle => Some(CantDoReason::NotAuthorized),
        Action::AdminCancel => match get_order(msg, ctx.pool()).await {
            Ok(order) if nobody_took(&order) => None,
            _ => Some(CantDoReason::NotAuthorized),
        },
        _ => None,
    }
}

/// The orders `admin_cancel_action` lets the daemon key cancel: not taken, so no escrow and no
/// dispute (`Pending`, `WaitingTakerBond`, `WaitingMakerBond`).
fn nobody_took(order: &Order) -> bool {
    [
        Status::Pending,
        Status::WaitingTakerBond,
        Status::WaitingMakerBond,
    ]
    .into_iter()
    .any(|status| order.check_status(status).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::context::test_utils::{test_settings, TestContextBuilder};
    use mostro_core::db::Crud;
    use mostro_core::order::Order;
    use nostr_sdk::prelude::Timestamp;
    use std::sync::Arc;

    async fn ctx() -> AppContext {
        let pool = Arc::new(sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap());
        sqlx::migrate!("./migrations")
            .run(pool.as_ref())
            .await
            .unwrap();
        TestContextBuilder::new()
            .with_pool(pool)
            .with_settings(test_settings())
            .build()
    }

    async fn order_with_status(ctx: &AppContext, status: &str) -> uuid::Uuid {
        let order = Order {
            id: uuid::Uuid::new_v4(),
            kind: "sell".to_string(),
            status: status.to_string(),
            creator_pubkey: "aa".repeat(32),
            seller_pubkey: Some("aa".repeat(32)),
            fiat_code: "USD".to_string(),
            payment_method: "bank".to_string(),
            amount: 100_000,
            fiat_amount: 100,
            ..Default::default()
        };
        order.create(ctx.pool()).await.unwrap().id
    }

    /// `action` on `order`, from `identity` (and its trade key `sender`), as a relay event.
    fn event(
        action: Action,
        order: uuid::Uuid,
        sender: &Keys,
        identity: &Keys,
    ) -> UnwrappedMessage {
        UnwrappedMessage {
            message: Message::new_order(Some(order), Some(1), None, action, None),
            signature: None,
            sender: sender.public_key(),
            identity: identity.public_key(),
            created_at: Timestamp::now(),
        }
    }

    async fn ask(
        ctx: &AppContext,
        action: Action,
        order: uuid::Uuid,
        from: &Keys,
        node: &Keys,
    ) -> Option<CantDoReason> {
        let unwrapped = event(action.clone(), order, from, from);
        refusal(ctx, &action, &unwrapped.message, &unwrapped, node).await
    }

    #[tokio::test]
    async fn the_daemon_key_cannot_take_a_dispute_over_nostr() {
        let ctx = ctx().await;
        let node = Keys::generate();
        let order = order_with_status(&ctx, "dispute").await;
        assert_eq!(
            ask(&ctx, Action::AdminTakeDispute, order, &node, &node).await,
            Some(CantDoReason::InvalidPubkey)
        );
    }

    #[tokio::test]
    async fn the_daemon_key_cannot_settle_or_cancel_a_dispute_over_nostr() {
        let ctx = ctx().await;
        let node = Keys::generate();
        let order = order_with_status(&ctx, "dispute").await;
        for action in [Action::AdminSettle, Action::AdminCancel] {
            assert_eq!(
                ask(&ctx, action.clone(), order, &node, &node).await,
                Some(CantDoReason::NotAuthorized),
                "{action:?}"
            );
        }
        let active = order_with_status(&ctx, "active").await;
        assert_eq!(
            ask(&ctx, Action::AdminCancel, active, &node, &node).await,
            Some(CantDoReason::NotAuthorized)
        );
    }

    #[tokio::test]
    async fn the_daemon_key_as_a_trade_key_alone_is_refused_too() {
        let ctx = ctx().await;
        let node = Keys::generate();
        let someone = Keys::generate();
        let order = order_with_status(&ctx, "dispute").await;
        let unwrapped = event(Action::AdminSettle, order, &node, &someone);
        assert_eq!(
            refusal(
                &ctx,
                &Action::AdminSettle,
                &unwrapped.message,
                &unwrapped,
                &node
            )
            .await,
            Some(CantDoReason::NotAuthorized)
        );
    }

    #[tokio::test]
    async fn operator_actions_keep_the_daemon_key() {
        let ctx = ctx().await;
        let node = Keys::generate();
        for status in ["pending", "waiting-taker-bond", "waiting-maker-bond"] {
            let order = order_with_status(&ctx, status).await;
            assert_eq!(
                ask(&ctx, Action::AdminCancel, order, &node, &node).await,
                None,
                "{status}"
            );
        }
        let order = order_with_status(&ctx, "pending").await;
        assert_eq!(
            ask(&ctx, Action::AdminAddSolver, order, &node, &node).await,
            None
        );
    }

    #[tokio::test]
    async fn solvers_are_not_touched() {
        let ctx = ctx().await;
        let node = Keys::generate();
        let solver = Keys::generate();
        let order = order_with_status(&ctx, "dispute").await;
        for action in [
            Action::AdminTakeDispute,
            Action::AdminSettle,
            Action::AdminCancel,
        ] {
            assert_eq!(
                ask(&ctx, action.clone(), order, &solver, &node).await,
                None,
                "{action:?}"
            );
        }
    }
}
