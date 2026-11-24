//! bipnip (upstream MostroP2P/mostro#1078): a hold invoice stays watched when LND restarts.
//!
//! The daemon used to subscribe to each hold invoice once. When LND restarted, every stream ended
//! and nothing subscribed again until the daemon itself restarted: a seller's payment went unseen
//! and the order sat in `waiting-payment` with the seller's sats locked. [`keep_watching`]
//! subscribes again, with a capped backoff, whenever a stream ends or fails. LND replays an
//! invoice's current state on every new subscription, and the handlers already take replays (the
//! startup resubscribe relies on that).

use std::future::Future;
use std::time::Duration;

use fedimint_tonic_lnd::lnrpc::invoice::InvoiceState;
use tokio::sync::mpsc::{channel, Sender};

use super::InvoiceMessage;

/// The first wait before subscribing again.
pub const FIRST_BACKOFF: Duration = Duration::from_secs(1);
/// The longest wait between two subscriptions.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Watches one hold invoice for as long as it matters.
///
/// `subscribe` streams the invoice's states into the sender it is given, and returns when its
/// stream ends (`Ok`) or fails (`Err`). Every state goes on to `out`. When a stream ends, the
/// invoice is subscribed again after a backoff that doubles up to [`MAX_BACKOFF`] (and starts
/// over once a subscription answers), unless:
/// - the last state seen was final (settled or canceled);
/// - `still_wanted` says nothing waits on the invoice any more (its order or bond left the
///   states the startup resubscribe selects);
/// - nobody reads `out` any more.
pub async fn keep_watching<S, SF, W, WF>(
    hash: Vec<u8>,
    out: Sender<InvoiceMessage>,
    mut subscribe: S,
    mut still_wanted: W,
    first_backoff: Duration,
) where
    S: FnMut(Vec<u8>, Sender<InvoiceMessage>) -> SF,
    SF: Future<Output = Result<(), String>>,
    W: FnMut() -> WF,
    WF: Future<Output = bool>,
{
    let hash_hex = crate::util::bytes_to_string(&hash);
    let mut backoff = first_backoff;
    loop {
        let (tx, mut rx) = channel(100);
        // The forwarder owns the receiver: once it stops, the subscriber's next send fails.
        let out_now = out.clone();
        let forward = async move {
            let out = out_now;
            let (mut answered, mut last) = (false, None);
            while let Some(message) = rx.recv().await {
                answered = true;
                last = Some(message.state);
                if out.send(message).await.is_err() {
                    return (answered, last, false);
                }
            }
            (answered, last, true)
        };
        let (result, (answered, last, read)) = tokio::join!(subscribe(hash.clone(), tx), forward);
        if !read {
            return;
        }
        if matches!(last, Some(InvoiceState::Settled | InvoiceState::Canceled)) {
            return;
        }
        if !still_wanted().await {
            tracing::info!(
                "hold invoice {hash_hex}: nothing waits on it any more; not watched again"
            );
            return;
        }
        if answered {
            backoff = first_backoff;
        }
        match result {
            Ok(()) => tracing::warn!(
                "hold invoice {hash_hex}: its subscription ended; subscribing again in {backoff:?}"
            ),
            Err(e) => tracing::warn!(
                "hold invoice {hash_hex}: its subscription failed ({e}); subscribing again in {backoff:?}"
            ),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    type Attempt = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

    /// A subscriber whose n-th call sends the n-th list of states, then ends (`true`) or fails.
    fn scripted(
        script: Vec<(Vec<InvoiceState>, bool)>,
        calls: Arc<AtomicUsize>,
    ) -> impl FnMut(Vec<u8>, Sender<InvoiceMessage>) -> Attempt {
        let script = Arc::new(Mutex::new(script.into_iter()));
        move |hash, tx| {
            calls.fetch_add(1, Ordering::SeqCst);
            let next = script.lock().unwrap().next();
            Box::pin(async move {
                let Some((states, ends_well)) = next else {
                    return Err("no more scripted attempts".to_string());
                };
                for state in states {
                    if tx
                        .send(InvoiceMessage {
                            hash: hash.clone(),
                            state,
                        })
                        .await
                        .is_err()
                    {
                        return Err("the receiver is gone".to_string());
                    }
                }
                if ends_well {
                    Ok(())
                } else {
                    Err("LND went away".to_string())
                }
            })
        }
    }

    fn always(wanted: bool) -> impl FnMut() -> Pin<Box<dyn Future<Output = bool> + Send>> {
        move || Box::pin(async move { wanted })
    }

    async fn drain(mut rx: tokio::sync::mpsc::Receiver<InvoiceMessage>) -> Vec<InvoiceState> {
        let mut seen = Vec::new();
        while let Some(message) = rx.recv().await {
            seen.push(message.state);
        }
        seen
    }

    #[tokio::test]
    async fn a_stream_that_ends_is_subscribed_again_until_the_invoice_is_final() {
        let calls = Arc::new(AtomicUsize::new(0));
        let script = vec![
            (vec![InvoiceState::Open], true),
            (vec![], false),
            (vec![InvoiceState::Open, InvoiceState::Accepted], true),
            (vec![InvoiceState::Accepted, InvoiceState::Settled], true),
            (vec![InvoiceState::Settled], true),
        ];
        let (out, rx) = channel(100);
        keep_watching(
            vec![7; 32],
            out,
            scripted(script, calls.clone()),
            always(true),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "it stops at the final state"
        );
        let seen = drain(rx).await;
        assert!(seen.contains(&InvoiceState::Accepted), "{seen:?}");
        assert_eq!(seen.last(), Some(&InvoiceState::Settled), "{seen:?}");
    }

    #[tokio::test]
    async fn a_canceled_invoice_is_not_watched_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let script = vec![(vec![InvoiceState::Canceled], true), (vec![], true)];
        let (out, _rx) = channel(100);
        keep_watching(
            vec![7; 32],
            out,
            scripted(script, calls.clone()),
            always(true),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_invoice_nobody_waits_on_is_not_watched_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let script = vec![
            (vec![InvoiceState::Open], true),
            (vec![InvoiceState::Open], true),
        ];
        let (out, _rx) = channel(100);
        keep_watching(
            vec![7; 32],
            out,
            scripted(script, calls.clone()),
            always(false),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failures_back_off_and_the_next_answer_gets_through() {
        let calls = Arc::new(AtomicUsize::new(0));
        let script = vec![
            (vec![], false),
            (vec![], false),
            (vec![], false),
            (vec![InvoiceState::Accepted], true),
            (vec![InvoiceState::Canceled], true),
        ];
        let (out, rx) = channel(100);
        keep_watching(
            vec![7; 32],
            out,
            scripted(script, calls.clone()),
            always(true),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert_eq!(
            drain(rx).await,
            vec![InvoiceState::Accepted, InvoiceState::Canceled]
        );
    }

    #[tokio::test]
    async fn it_stops_when_nobody_reads_the_states() {
        let calls = Arc::new(AtomicUsize::new(0));
        let script = vec![
            (vec![InvoiceState::Open], true),
            (vec![InvoiceState::Open], true),
        ];
        let (out, rx) = channel(100);
        drop(rx);
        keep_watching(
            vec![7; 32],
            out,
            scripted(script, calls.clone()),
            always(true),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_backoff_is_capped() {
        assert!(FIRST_BACKOFF < MAX_BACKOFF);
        assert!(MAX_BACKOFF <= Duration::from_secs(60));
    }
}
