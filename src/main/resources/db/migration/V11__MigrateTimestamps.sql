ALTER TABLE accounts
ALTER COLUMN creation_time TYPE TIMESTAMP WITH TIME ZONE USING creation_time AT TIME ZONE 'UTC' ;

ALTER TABLE client_authorizations
ALTER COLUMN creation_time TYPE TIMESTAMP WITH TIME ZONE USING creation_time AT TIME ZONE 'UTC',
ALTER COLUMN last_update_time TYPE TIMESTAMP WITH TIME ZONE USING last_update_time AT TIME ZONE 'UTC',
ALTER COLUMN authorization_code_issued_at TYPE TIMESTAMP WITH TIME ZONE USING authorization_code_issued_at AT TIME ZONE 'UTC',
ALTER COLUMN authorization_code_expires_at TYPE TIMESTAMP WITH TIME ZONE USING authorization_code_expires_at AT TIME ZONE 'UTC',
ALTER COLUMN access_token_issued_at TYPE TIMESTAMP WITH TIME ZONE USING access_token_issued_at AT TIME ZONE 'UTC',
ALTER COLUMN access_token_expires_at TYPE TIMESTAMP WITH TIME ZONE USING access_token_expires_at AT TIME ZONE 'UTC',
ALTER COLUMN refresh_token_issued_at TYPE TIMESTAMP WITH TIME ZONE USING refresh_token_issued_at AT TIME ZONE 'UTC',
ALTER COLUMN refresh_token_expires_at TYPE TIMESTAMP WITH TIME ZONE USING refresh_token_expires_at AT TIME ZONE 'UTC' ;

ALTER TABLE client_consent_logs
ALTER COLUMN timestamp TYPE TIMESTAMP WITH TIME ZONE USING timestamp AT TIME ZONE 'UTC' ;

ALTER TABLE client_registrations
ALTER COLUMN creation_time TYPE TIMESTAMP WITH TIME ZONE USING creation_time AT TIME ZONE 'UTC' ;

ALTER TABLE gw2_account_verification_challenges
ALTER COLUMN started_at TYPE TIMESTAMP WITH TIME ZONE USING started_at AT TIME ZONE 'UTC',
ALTER COLUMN timeout_at TYPE TIMESTAMP WITH TIME ZONE USING timeout_at AT TIME ZONE 'UTC' ;

ALTER TABLE gw2_api_subtokens
ALTER COLUMN expiration_time TYPE TIMESTAMP WITH TIME ZONE USING expiration_time AT TIME ZONE 'UTC' ;

ALTER TABLE gw2_api_tokens
ALTER COLUMN creation_time TYPE TIMESTAMP WITH TIME ZONE USING creation_time AT TIME ZONE 'UTC',
ALTER COLUMN last_valid_check_time TYPE TIMESTAMP WITH TIME ZONE USING last_valid_check_time AT TIME ZONE 'UTC' ;