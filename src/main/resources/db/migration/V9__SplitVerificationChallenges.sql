CREATE TABLE temp_gw2_account_verification_challenges
AS SELECT * FROM gw2_account_verification_challenges ;

DROP TABLE gw2_account_verification_challenges ;

CREATE TABLE gw2_account_verification_challenges (
    account_id UUID NOT NULL,
    challenge_id BIGINT NOT NULL,
    state TEXT NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (account_id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ;

CREATE TABLE gw2_account_verification_pending_challenges (
    account_id UUID NOT NULL,
    gw2_account_id UUID NOT NULL,
    challenge_id BIGINT NOT NULL,
    state TEXT NOT NULL,
    gw2_api_token TEXT NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    submit_time TIMESTAMP WITH TIME ZONE NOT NULL,
    timeout_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (account_id, gw2_account_id),
    FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_accounts (account_id, gw2_account_id) ON DELETE CASCADE
) ;

-- copy data
INSERT INTO gw2_account_verification_challenges
(account_id, challenge_id, state, creation_time)
SELECT account_id, challenge_id, state, started_at
FROM temp_gw2_account_verification_challenges
WHERE gw2_account_id = '' ;

INSERT INTO gw2_account_verification_pending_challenges
(account_id, gw2_account_id, challenge_id, state, gw2_api_token, creation_time, submit_time, timeout_time)
SELECT account_id, gw2_account_id::UUID, challenge_id, state, gw2_api_token, started_at, started_at, timeout_at
FROM temp_gw2_account_verification_challenges
WHERE gw2_account_id <> '' ;

-- drop temp
DROP TABLE temp_gw2_account_verification_challenges ;

-- acls
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE gw2_account_verification_challenges TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE gw2_account_verification_pending_challenges TO gw2auth_app ;