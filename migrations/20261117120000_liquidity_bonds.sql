-- bipnip: bonds on liquidity orders (src/app/liquidity_bond.rs).
-- A new table only; Mostro's own `bonds` table and code are untouched.
--
-- Each row is one hold invoice on this instance's node, paid by a member of a ring (or the buyer
-- of a lease) before anything is opened. This is the only liquidity table that stands for money
-- the instance holds.
CREATE TABLE IF NOT EXISTS liquidity_bonds (
  id char(36) primary key not null,
  -- ring | lease
  kind varchar(8) not null,
  -- ring_offers.id or lease_offers.id
  order_id char(36) not null,
  -- Who paid it: the member's node-bound identity key and the trade key replies go to.
  payer_identity char(64) not null,
  payer_trade_pubkey char(64) not null,
  amount_sat integer not null,
  payment_hash char(64) not null unique,
  -- The preimage of the hold invoice. Revealed to the node only when the bond is taken.
  preimage char(64) not null,
  invoice text not null,
  -- requested | locked | released | slashed | claimed | paid | forfeited
  state varchar(12) not null,
  -- 0 while the node call that goes with `released` (cancel) or `slashed` (settle) is still
  -- owed; the housekeeping job repeats it until it is 1.
  node_done integer not null default 1,
  -- Announced channels that already existed between the payer's node and the node it must open
  -- to, when the bond was locked (JSON array of outpoints). They do not count as the opening.
  graph_before text,
  -- Once taken: who it is owed to.
  recipient_identity char(64),
  recipient_trade_pubkey char(64),
  slashed_at integer,
  -- The invoice the recipient sent for it, while a payout is under way.
  payout_invoice text,
  payout_hash char(64),
  payout_expires_at integer,
  payout_attempts integer not null default 0,
  created_at integer not null,
  unique (kind, order_id, payer_identity)
);
CREATE INDEX IF NOT EXISTS idx_liquidity_bonds_order ON liquidity_bonds (kind, order_id);
CREATE INDEX IF NOT EXISTS idx_liquidity_bonds_state ON liquidity_bonds (state);
