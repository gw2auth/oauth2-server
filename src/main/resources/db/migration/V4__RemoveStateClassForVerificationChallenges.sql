ALTER TABLE gw2_account_verification_challenges
DROP COLUMN state_class ;

ALTER TABLE gw2_account_verification_challenges
ALTER COLUMN state DROP NOT NULL ;

-- convert the json string the APITokenNameVerificationChallenge previously put in here to just the string itself
UPDATE gw2_account_verification_challenges
SET state = state::json#>>'{}'
WHERE challenge_id = 1 ;
