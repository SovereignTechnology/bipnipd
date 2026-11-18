-- bipnip: a seller may send a fresh completion invoice once the one before expired unpaid
-- (src/app/lease.rs, `seller_step`). Both columns are this instance's own bookkeeping.
-- When the last completion invoice sent stops being payable, unix seconds.
ALTER TABLE leases ADD COLUMN completion_expires_at integer;
-- How many completion invoices the seller has sent for this lease.
ALTER TABLE leases ADD COLUMN completion_count integer not null default 0;
