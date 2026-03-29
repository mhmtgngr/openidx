-- Rollback 004: Governance Tables

DROP TABLE IF EXISTS policy_rules CASCADE;
DROP TABLE IF EXISTS policies CASCADE;
DROP TABLE IF EXISTS review_items CASCADE;
DROP TABLE IF EXISTS access_reviews CASCADE;
