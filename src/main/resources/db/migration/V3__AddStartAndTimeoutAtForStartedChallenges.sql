UPDATE gw2_account_verification_challenges
SET
    started_at = NOW(),
    timeout_at = NOW() + INTERVAL '30 MINUTES'
WHERE gw2_account_id = '' ;

ALTER TABLE gw2_account_verification_challenges
ALTER COLUMN started_at SET NOT NULL ;

ALTER TABLE gw2_account_verification_challenges
ALTER COLUMN timeout_at SET NOT NULL ;