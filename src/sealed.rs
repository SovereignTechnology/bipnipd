//! bipnip: hold-invoice preimages are sealed at rest.
//!
//! A preimage is what settles a hold invoice: whoever has it, and can reach the node, can take an
//! escrow before the buyer has paid, or a bond before its verdict. Upstream keeps them in the
//! database in cleartext (it dropped its own database encryption), so a copied database file or a
//! backup was enough. Each preimage is now stored as `sealed1:` and a NIP-44 v2 ciphertext to the
//! daemon's own key, bound to its row (`orders/<id>`, `bonds/<id>`, `liquidity_bonds/<id>`), so a
//! sealed value moved to another row does not open.
//!
//! A value without the prefix was stored before sealing, and is read as it is. Rotating the
//! daemon's key strands the sealed preimages: settle or cancel what is held first.

use mostro_core::error::{MostroError, MostroError::MostroInternalErr, ServiceError};
use nostr_sdk::prelude::{nip44, Keys};

/// The prefix of a sealed value.
pub const PREFIX: &str = "sealed1:";

fn sealing_error(why: impl std::fmt::Display) -> MostroError {
    MostroInternalErr(ServiceError::UnexpectedError(format!(
        "sealed preimage: {why}"
    )))
}

/// The key preimages are sealed to: the daemon's own.
fn keys() -> Result<&'static Keys, MostroError> {
    #[cfg(test)]
    {
        static TEST: std::sync::LazyLock<Keys> = std::sync::LazyLock::new(Keys::generate);
        Ok(crate::config::get_mostro_keys().unwrap_or(&TEST))
    }
    #[cfg(not(test))]
    {
        crate::util::get_keys()
    }
}

/// `preimage` sealed for `row`.
pub fn seal(row: &str, preimage: &str) -> Result<String, MostroError> {
    let keys = keys()?;
    let sealed = nip44::encrypt(
        keys.secret_key(),
        &keys.public_key(),
        format!("{row}\n{preimage}"),
        nip44::Version::V2,
    )
    .map_err(sealing_error)?;
    Ok(format!("{PREFIX}{sealed}"))
}

/// The preimage `stored` for `row` holds: opened, or as it is when it was stored before sealing.
pub fn open(row: &str, stored: &str) -> Result<String, MostroError> {
    let Some(sealed) = stored.strip_prefix(PREFIX) else {
        return Ok(stored.to_string());
    };
    let keys = keys()?;
    let plain =
        nip44::decrypt(keys.secret_key(), &keys.public_key(), sealed).map_err(sealing_error)?;
    match plain.split_once('\n') {
        Some((bound, preimage)) if bound == row => Ok(preimage.to_string()),
        _ => Err(sealing_error(format!("not sealed for {row}"))),
    }
}

/// The tables that hold preimages, by the name their rows are sealed under.
const TABLES: [&str; 3] = ["orders", "bonds", "liquidity_bonds"];

/// Seals every preimage still stored in cleartext, at startup. A row changed meanwhile is left
/// as it is (compare-and-swap) and read as cleartext, as before. Returns how many were sealed.
pub async fn seal_stored(pool: &sqlx::SqlitePool) -> Result<u64, MostroError> {
    use sqlx::Row;
    let db = |e: sqlx::Error| MostroInternalErr(ServiceError::DbAccessError(e.to_string()));
    let mut sealed = 0;
    for table in TABLES {
        // The table names are the constants above, never input.
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT rowid AS r, id, preimage FROM {table} \
             WHERE preimage IS NOT NULL AND preimage NOT LIKE 'sealed1:%'"
        )))
        .fetch_all(pool)
        .await
        .map_err(db)?;
        for row in rows {
            let rowid: i64 = row.try_get("r").map_err(db)?;
            let preimage: String = row.try_get("preimage").map_err(db)?;
            // Orders and anti-abuse bonds keep their id as a UUID, liquidity bonds as text.
            let id = match row.try_get::<uuid::Uuid, _>("id") {
                Ok(id) => id.to_string(),
                Err(_) => row.try_get::<String, _>("id").map_err(db)?,
            };
            let value = seal(&format!("{table}/{id}"), &preimage)?;
            let done = sqlx::query(sqlx::AssertSqlSafe(format!(
                "UPDATE {table} SET preimage = ? WHERE rowid = ? AND preimage = ?"
            )))
            .bind(&value)
            .bind(rowid)
            .bind(&preimage)
            .execute(pool)
            .await
            .map_err(db)?;
            sealed += done.rows_affected();
        }
    }
    Ok(sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preimages_stored_in_cleartext_are_sealed_at_startup() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let order = uuid::Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO orders (id, kind, event_id, status, premium, payment_method,
                    amount, fiat_code, fiat_amount, created_at, expires_at,
                    failed_payment, payment_attempts, dev_fee, dev_fee_paid, preimage)
            VALUES (?1, 'sell', 'ev1', 'active', 0, 'bank', 100000, 'USD', 100,
                    1700000000, 1700086400, 0, 0, 0, 0, ?2)"#,
        )
        .bind(order)
        .bind(PREIMAGE)
        .execute(&pool)
        .await
        .unwrap();
        let empty = uuid::Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO orders (id, kind, event_id, status, premium, payment_method,
                    amount, fiat_code, fiat_amount, created_at, expires_at,
                    failed_payment, payment_attempts, dev_fee, dev_fee_paid)
            VALUES (?1, 'sell', 'ev2', 'pending', 0, 'bank', 100000, 'USD', 100,
                    1700000000, 1700086400, 0, 0, 0, 0)"#,
        )
        .bind(empty)
        .execute(&pool)
        .await
        .unwrap();

        assert_eq!(seal_stored(&pool).await.unwrap(), 1);
        // Orders keep their id as a UUID, as the daemon writes it.
        let stored: String = sqlx::query_scalar("SELECT preimage FROM orders WHERE id = ?")
            .bind(order)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(stored.starts_with(PREFIX));
        assert_eq!(open(&format!("orders/{order}"), &stored).unwrap(), PREIMAGE);
        // Once sealed, nothing more to do; an order without a preimage keeps none.
        assert_eq!(seal_stored(&pool).await.unwrap(), 0);
        let none: Option<String> = sqlx::query_scalar("SELECT preimage FROM orders WHERE id = ?")
            .bind(empty)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(none, None);
    }

    const PREIMAGE: &str = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00";

    #[test]
    fn a_sealed_preimage_hides_it_and_opens_for_its_row_only() {
        let sealed = seal("orders/1", PREIMAGE).unwrap();
        assert!(sealed.starts_with(PREFIX), "{sealed}");
        assert!(!sealed.contains(PREIMAGE));
        assert_eq!(open("orders/1", &sealed).unwrap(), PREIMAGE);
        // Moved to another row, it does not open.
        assert!(open("orders/2", &sealed).is_err());
        assert!(open("bonds/1", &sealed).is_err());
        // Sealing twice gives two different values.
        assert_ne!(seal("orders/1", PREIMAGE).unwrap(), sealed);
    }

    #[test]
    fn a_changed_seal_does_not_open() {
        let sealed = seal("bonds/7", PREIMAGE).unwrap();
        let body = sealed.strip_prefix(PREFIX).unwrap();
        let mut bytes: Vec<char> = body.chars().collect();
        let mid = bytes.len() / 2;
        bytes[mid] = if bytes[mid] == 'A' { 'B' } else { 'A' };
        let changed = format!("{PREFIX}{}", bytes.into_iter().collect::<String>());
        assert!(open("bonds/7", &changed).is_err());
        assert!(open("bonds/7", &format!("{PREFIX}not a ciphertext")).is_err());
    }

    #[test]
    fn a_preimage_stored_before_sealing_reads_as_it_is() {
        assert_eq!(open("orders/1", PREIMAGE).unwrap(), PREIMAGE);
    }
}
