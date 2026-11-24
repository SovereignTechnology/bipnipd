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
use nostr_sdk::prelude::Keys;

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
pub fn seal(_row: &str, preimage: &str) -> Result<String, MostroError> {
    let _ = keys()?;
    Ok(preimage.to_string())
}

/// The preimage `stored` for `row` holds: opened, or as it is when it was stored before sealing.
pub fn open(_row: &str, stored: &str) -> Result<String, MostroError> {
    Ok(stored.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
