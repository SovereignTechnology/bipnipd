-- bipnip: liquidity rings (docs: bipnip repo, docs/nips/liquidity-rings.md).
-- New tables only. A ring moves no money through the instance, and nothing here holds any.

-- A creator's ring and where it stands.
CREATE TABLE IF NOT EXISTS ring_offers (
  id char(36) primary key not null,
  creator_identity char(64) not null,
  network varchar(10) not null,
  -- The offer as received (JSON); already validated, with a verified binding.
  offer text not null,
  slots integer not null,
  -- Slots taken, the creator's included. Changed only by compare-and-swap updates.
  taken integer not null,
  -- pending | committing | open | success | partial | canceled | expired
  status varchar(12) not null,
  -- The roster's canonical text and its id, once every slot is taken.
  ring text,
  ring_id char(64),
  window_ends_at integer,
  created_at integer not null,
  expires_at integer not null,
  -- "<status>:<taken>" the public order event was last brought up to date with; NULL = never.
  synced varchar(24),
  -- created_at of the last order event published, so the next one is always newer.
  order_event_at integer
);
CREATE INDEX IF NOT EXISTS idx_ring_offers_creator ON ring_offers (creator_identity, status);

-- The members of a ring: one row per slot taken.
CREATE TABLE IF NOT EXISTS ring_members (
  ring_offer_id char(36) not null references ring_offers (id),
  -- The member's node-bound identity key (hex) and the trade key replies go to.
  identity char(64) not null,
  trade_pubkey char(64) not null,
  node char(66) not null,
  -- The seat as received (JSON): node, binding event, node address.
  seat text not null,
  -- Place in the opening order, from 0; set when the roster is fixed.
  position integer,
  -- The member's signature of the ring id.
  commit_sig char(128),
  -- The channel this member says it opened to the next member: a claim.
  edge_txid char(64),
  edge_index integer,
  -- 1 once the member it opened to confirmed that channel.
  edge_verified integer not null default 0,
  joined_at integer not null,
  primary key (ring_offer_id, identity),
  unique (ring_offer_id, node)
);
