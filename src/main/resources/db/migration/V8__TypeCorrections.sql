-- remove fk checks
ALTER TABLE client_authorization_tokens
DROP CONSTRAINT client_authorization_tokens_account_id_gw2_account_id_fkey ;

ALTER TABLE gw2_api_subtokens
DROP CONSTRAINT gw2_api_subtokens_account_id_gw2_account_id_fkey ;

-- migrate
ALTER TABLE account_federations
ALTER COLUMN issuer TYPE TEXT,
ALTER COLUMN id_at_issuer TYPE TEXT ;

ALTER TABLE client_authorization_tokens
ALTER COLUMN client_authorization_id TYPE TEXT,
ALTER COLUMN gw2_account_id TYPE UUID USING gw2_account_id::UUID ;

ALTER TABLE client_authorizations
ALTER COLUMN id TYPE TEXT,
ALTER COLUMN display_name TYPE TEXT,
ALTER COLUMN authorization_grant_type TYPE TEXT,
ALTER COLUMN authorized_scopes TYPE TEXT[],
ALTER COLUMN attributes TYPE TEXT,
ALTER COLUMN state TYPE TEXT,
ALTER COLUMN authorization_code_value TYPE TEXT,
ALTER COLUMN authorization_code_metadata TYPE TEXT,
ALTER COLUMN access_token_value TYPE TEXT,
ALTER COLUMN access_token_metadata TYPE TEXT,
ALTER COLUMN access_token_type TYPE TEXT,
ALTER COLUMN access_token_scopes TYPE TEXT[],
ALTER COLUMN refresh_token_value TYPE TEXT,
ALTER COLUMN refresh_token_metadata TYPE TEXT ;

ALTER TABLE client_consent_logs
ALTER COLUMN type TYPE TEXT,
ALTER COLUMN messages TYPE TEXT[] ;

ALTER TABLE client_consents
ALTER COLUMN authorized_scopes TYPE TEXT[] ;

ALTER TABLE client_registrations
ALTER COLUMN display_name TYPE TEXT,
ALTER COLUMN client_id TYPE UUID USING client_id::UUID,
ALTER COLUMN client_secret TYPE TEXT,
ALTER COLUMN authorization_grant_types TYPE TEXT[] ;

ALTER TABLE gw2_account_verification_challenges
ALTER COLUMN state TYPE TEXT,
ALTER COLUMN gw2_api_token TYPE TEXT ;

ALTER TABLE gw2_account_verifications
ALTER COLUMN gw2_account_id TYPE UUID USING gw2_account_id::UUID;

ALTER TABLE gw2_api_subtokens
ALTER COLUMN gw2_account_id TYPE UUID USING gw2_account_id::UUID,
ALTER COLUMN gw2_api_subtoken TYPE TEXT ;

ALTER TABLE gw2_api_tokens
ALTER COLUMN gw2_account_id TYPE UUID USING gw2_account_id::UUID,
ALTER COLUMN gw2_api_token TYPE TEXT,
ALTER COLUMN gw2_api_permissions TYPE TEXT[],
ALTER COLUMN display_name TYPE TEXT ;

-- add fk checks
ALTER TABLE client_authorization_tokens
ADD FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_api_tokens (account_id, gw2_account_id) ON DELETE CASCADE ;

ALTER TABLE gw2_api_subtokens
ADD FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_api_tokens (account_id, gw2_account_id) ON DELETE CASCADE ;
