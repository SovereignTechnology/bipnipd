-- bipnip: liquidity leases (docs: bipnip repo, docs/nips/liquidity-leases.md).
-- New tables only: upstream's tables are not altered, so upstream release merges stay clean.
-- The instance coordinates a lease; it never holds the lease payment or its preimage, and no
-- column here can store either.

-- A seller's offer, and the state of the one lease taken from it.
CREATE TABLE IF NOT EXISTS lease_offers (
  id char(36) primary key not null,
  -- The seller's node-bound identity key (hex) and the trade key replies go to.
  seller_identity char(64) not null,
  seller_trade_pubkey char(64) not null,
  seller_node char(66) not null,
  network varchar(10) not null,
  -- The offer as received (JSON); already validated, with a verified binding.
  offer text not null,
  -- pending | taken | invoiced | opened | active | completion | canceled
  status varchar(12) not null,
  created_at integer not null,
  expires_at integer not null
);
CREATE INDEX IF NOT EXISTS idx_lease_offers_seller ON lease_offers (seller_identity, status);

-- The take of an offer: one per offer.
CREATE TABLE IF NOT EXISTS leases (
  -- The contract id (sha256 of the canonical contract text, hex).
  lease_id char(64) primary key not null,
  offer_id char(36) not null unique references lease_offers (id),
  buyer_identity char(64) not null,
  buyer_trade_pubkey char(64) not null,
  buyer_node char(66) not null,
  -- The canonical contract text: terms, both nodes and the payment hash.
  contract text not null,
  -- The funding outpoint the seller reported; a claim, not something the instance verified.
  funding_txid char(64),
  output_index integer,
  created_at integer not null,
  updated_at integer not null
);
