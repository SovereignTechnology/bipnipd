-- bipnip: outcomes (kind 8735) this instance signs about the rings and lease bonds it
-- coordinated, kept until a relay takes them (src/app/liquidity_outcome.rs).
CREATE TABLE IF NOT EXISTS liquidity_outcomes (
  id integer primary key autoincrement,
  -- lease | ring
  deal text not null,
  -- The lease id or the ring id (hex).
  subject char(64) not null,
  network text not null,
  -- The seller or the opener, then the buyer or the receiver (node keys, hex).
  node_a char(66) not null,
  node_b char(66) not null,
  -- kept | closed-early | unpaid | slashed | opened | missing
  result text not null,
  outpoint text,
  -- When it was decided: the event's time, the same on every attempt.
  created_at integer not null,
  published integer not null default 0,
  unique (subject, node_a, node_b)
);
