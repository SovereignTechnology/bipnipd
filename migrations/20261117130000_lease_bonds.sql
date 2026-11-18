-- bipnip: the buyer's bond on a lease (src/app/lease.rs, src/app/liquidity_bond.rs).
-- Our own table only. When an offer asks for a bond, the take is kept here until the buyer's
-- bond is locked, and only then passed on to the seller.
ALTER TABLE leases ADD COLUMN take text;
-- The request id the buyer sent its take under, for the answer it gets once the bond is locked.
ALTER TABLE leases ADD COLUMN take_request_id integer;
