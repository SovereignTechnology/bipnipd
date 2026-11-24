-- bipnip: the block height at which a ring's or a lease's bond verdict first fell due. The verdict
-- waits `[liquidity] bond_grace_blocks` more blocks from there, so a channel whose announcement
-- gossip has not brought yet is not judged missing (src/app/liquidity_bond.rs, `grace_over`).
CREATE TABLE IF NOT EXISTS liquidity_verdict_waits (
  -- ring | lease
  kind text not null,
  order_id char(36) not null,
  first_height integer not null,
  primary key (kind, order_id)
);
