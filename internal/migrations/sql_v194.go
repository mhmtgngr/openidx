package migrations

// Migration v194 -- the webhook queue gets a claim, so the sweep stops
// multiplying the backlog and the backoff starts being honoured.
//
// THE QUEUE IS REDIS AND THE RECORD IS POSTGRESQL, and until now nothing wrote
// down which deliveries were already on the queue. Publish INSERTs a row as
// `pending` and nudges Redis; processRetryBatch scans for pending rows and
// pushes them back, so a nudge lost to a Redis blip is still delivered. That
// backstop is right. What it could not tell was the difference between a
// delivery nobody has queued and one the consumer simply has not reached yet --
// a row stays `pending` for its whole life in the queue AND for the whole HTTP
// call. So every thirty seconds the entire undrained backlog was enqueued
// again. Measured: four entries for one event after three ticks, and eighty for
// twenty deliveries when four sweeps ran at once, which is what a Redis outage
// does to the leader gate that was the only thing holding it to one.
//
// That is not at-least-once delivery. At-least-once is a delivery that may
// repeat; this was a feedback loop whose output grew with how far behind the
// consumer already was, which means it grew fastest exactly when the consumer
// was already struggling.
//
// WHY A SECOND COLUMN RATHER THAN REUSING next_retry_at. The two answer
// different questions and the first attempt at this fix proved it by breaking:
// next_retry_at is WHEN A DELIVERY BECOMES DUE (the one, five and thirty minute
// backoff), and queued_at is WHETHER SOMEONE ALREADY HAS IT. Folding the claim
// into next_retry_at made the sweep's own claim look, to the consumer, like a
// delivery that was not due yet -- so the sweep enqueued the delivery and the
// consumer then refused it, and the customer's endpoint was called zero times.
// One column cannot hold both meanings because the sweep must be able to hand a
// row to a consumer it has just claimed.
//
// The claim also repairs the backoff, which was written down and defeated one
// line later: scheduleRetry stored next_retry_at and then pushed the id
// straight back onto the queue, where a consumer blocked on BRPop took it
// within milliseconds. All three attempts were spent in under a second and the
// delivery was marked `failed`, so a retry policy meant to ride out a
// thirty-six minute outage rode out nothing -- a customer endpoint that
// restarted in ten seconds had already lost the event. With queued_at carrying
// the claim, next_retry_at is free to mean what it says and the sweep is the
// only thing that schedules.
//
// Existing rows get NULL, which reads as "nobody has claimed this" -- the safe
// direction, and the branch the sweep keeps for it is the original thirty
// second grace, so a delivery in flight across the upgrade is picked up once
// rather than lost.
var webhookDeliveryClaimUp = `-- Migration 194: a claim marker for the webhook delivery queue.
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS queued_at TIMESTAMPTZ;

-- PARTIAL on status, for the reason the outbox's backlog index is partial: a
-- delivered webhook is never wanted by the sweep again, and within a day the
-- delivered rows are the overwhelming majority. An index the size of the
-- BACKLOG answers the sweep's query at constant cost while the table grows.
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_claimable
    ON webhook_deliveries (queued_at, next_retry_at)
    WHERE status = 'pending';
`

// Down drops both. The sweep reverts to its previous behaviour -- delivering
// everything, and multiplying the queue while it does -- rather than breaking.
var webhookDeliveryClaimDown = `-- Migration 194 down.
DROP INDEX IF EXISTS idx_webhook_deliveries_claimable;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS queued_at;
`
