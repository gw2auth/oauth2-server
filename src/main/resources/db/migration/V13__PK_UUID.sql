-- create temp backup tables
CREATE TABLE accounts_bak AS SELECT * FROM accounts ;
CREATE TABLE account_federations_bak AS SELECT * FROM account_federations ;
CREATE TABLE account_federation_sessions_bak AS SELECT * FROM account_federation_sessions ;

CREATE TABLE gw2_api_tokens_bak AS SELECT * FROM gw2_api_tokens ;
CREATE TABLE gw2_api_subtokens_bak AS SELECT * FROM gw2_api_subtokens ;
CREATE TABLE gw2_account_verifications_bak AS SELECT * FROM gw2_account_verifications ;
CREATE TABLE gw2_account_verification_challenges_bak AS SELECT * FROM gw2_account_verification_challenges ;

CREATE TABLE client_registrations_bak AS SELECT * FROM client_registrations ;
CREATE TABLE client_consents_bak AS SELECT * FROM client_consents ;
CREATE TABLE client_consent_logs_bak AS SELECT * FROM client_consent_logs ;
CREATE TABLE client_authorizations_bak AS SELECT * FROM client_authorizations ;
CREATE TABLE client_authorization_tokens_bak AS SELECT * FROM client_authorization_tokens ;

-- drop old tables
DROP TABLE client_authorization_tokens ;
DROP TABLE client_authorizations ;
DROP TABLE client_consent_logs ;
DROP TABLE client_consents ;
DROP TABLE client_registrations ;

DROP TABLE gw2_account_verification_challenges ;
DROP TABLE gw2_account_verifications ;
DROP TABLE gw2_api_subtokens ;
DROP TABLE gw2_api_tokens ;

DROP TABLE account_federation_sessions ;
DROP TABLE account_federations ;
DROP TABLE accounts ;

-- create new tables
CREATE EXTENSION pg_trgm ;
CREATE EXTENSION btree_gin ;

CREATE TABLE accounts (
    id UUID NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id)
) ;

CREATE TABLE account_federations (
    issuer TEXT NOT NULL,
    id_at_issuer TEXT NOT NULL,
    account_id UUID NOT NULL,
    PRIMARY KEY (issuer, id_at_issuer),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ;

CREATE TABLE account_federation_sessions (
    id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    id_at_issuer TEXT NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    expiration_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (issuer, id_at_issuer) REFERENCES account_federations (issuer, id_at_issuer) ON DELETE CASCADE
) ;

CREATE TABLE gw2_api_tokens (
    account_id UUID NOT NULL,
    gw2_account_id UUID NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    gw2_api_token TEXT NOT NULL,
    gw2_api_permissions TEXT[] NOT NULL,
    display_name TEXT NOT NULL,
    last_valid_check_time TIMESTAMP WITH TIME ZONE NOT NULL,
    is_valid BOOL NOT NULL,
    PRIMARY KEY (account_id, gw2_account_id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
    CHECK ( LENGTH(display_name) BETWEEN 1 AND 100 )
) ;

CREATE INDEX ON gw2_api_tokens (last_valid_check_time) ;

CREATE TABLE gw2_api_subtokens (
    account_id UUID NOT NULL,
    gw2_account_id UUID NOT NULL,
    gw2_api_permissions_bit_set INT NOT NULL,
    gw2_api_subtoken TEXT NOT NULL,
    expiration_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (account_id, gw2_account_id, gw2_api_permissions_bit_set),
    FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_api_tokens (account_id, gw2_account_id) ON DELETE CASCADE
) ;

CREATE TABLE gw2_account_verifications (
    gw2_account_id UUID NOT NULL,
    account_id UUID NOT NULL,
    PRIMARY KEY (gw2_account_id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ;

CREATE TABLE gw2_account_verification_challenges (
    account_id UUID NOT NULL,
    gw2_account_id TEXT NOT NULL,
    challenge_id BIGINT NOT NULL,
    state TEXT,
    gw2_api_token TEXT,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    timeout_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (account_id, gw2_account_id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ;

CREATE TABLE client_registrations (
    id UUID NOT NULL,
    account_id UUID NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    display_name TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    authorization_grant_types TEXT[] NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
    CHECK ( LENGTH(display_name) BETWEEN 1 AND 100 ),
    CHECK ( ARRAY_LENGTH(redirect_uris, 1) BETWEEN 1 AND 50 )
) ;

CREATE TABLE client_consents (
    account_id UUID NOT NULL,
    client_registration_id UUID NOT NULL,
    account_sub UUID NOT NULL,
    authorized_scopes TEXT[] NOT NULL,
    PRIMARY KEY (account_id, client_registration_id),
    FOREIGN KEY (client_registration_id) REFERENCES client_registrations (id) ON DELETE CASCADE
) ;

CREATE TABLE client_consent_logs (
    id UUID NOT NULL,
    account_id UUID NOT NULL,
    client_registration_id UUID NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    type TEXT NOT NULL,
    messages TEXT[] NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (account_id, client_registration_id) REFERENCES client_consents (account_id, client_registration_id) ON DELETE CASCADE
) ;

CREATE INDEX ON client_consent_logs (account_id, client_registration_id, timestamp) ;

CREATE TABLE client_authorizations (
    id TEXT NOT NULL,
    account_id UUID NOT NULL,
    client_registration_id UUID NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    last_update_time TIMESTAMP WITH TIME ZONE NOT NULL,
    display_name TEXT NOT NULL,
    authorization_grant_type TEXT NOT NULL,
    authorized_scopes TEXT[] NOT NULL,
    attributes TEXT,
    state TEXT,
    authorization_code_value TEXT,
    authorization_code_issued_at TIMESTAMP WITH TIME ZONE,
    authorization_code_expires_at TIMESTAMP WITH TIME ZONE,
    authorization_code_metadata TEXT,
    access_token_value TEXT,
    access_token_issued_at TIMESTAMP WITH TIME ZONE,
    access_token_expires_at TIMESTAMP WITH TIME ZONE,
    access_token_metadata TEXT,
    access_token_type TEXT,
    access_token_scopes TEXT[] NOT NULL,
    refresh_token_value TEXT,
    refresh_token_issued_at TIMESTAMP WITH TIME ZONE,
    refresh_token_expires_at TIMESTAMP WITH TIME ZONE,
    refresh_token_metadata TEXT,
    PRIMARY KEY (id),
    FOREIGN KEY (account_id, client_registration_id) REFERENCES client_consents (account_id, client_registration_id) ON DELETE CASCADE,
    UNIQUE (state)
) ;

-- these columns are too large for a normal index, use hashed index
-- (no strong crypto requirements, thus using md5 instead of sha)
CREATE INDEX ON client_authorizations (md5(authorization_code_value)) ;
CREATE INDEX ON client_authorizations (md5(access_token_value)) ;
CREATE INDEX ON client_authorizations (md5(refresh_token_value)) ;

CREATE TABLE client_authorization_tokens (
    client_authorization_id TEXT NOT NULL,
    account_id UUID NOT NULL,
    gw2_account_id UUID NOT NULL,
    PRIMARY KEY (client_authorization_id, gw2_account_id),
    FOREIGN KEY (client_authorization_id) REFERENCES client_authorizations (id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_api_tokens (account_id, gw2_account_id) ON DELETE CASCADE
) ;

-- create helper table for new UUID pks
CREATE TABLE ids_temp (
    tbl TEXT NOT NULL,
    old_id BIGINT NOT NULL,
    new_id UUID NOT NULL,
    PRIMARY KEY (tbl, old_id),
    UNIQUE (tbl, new_id)
) ;

INSERT INTO ids_temp (tbl, old_id, new_id)
SELECT 'accounts', id, gen_random_uuid() FROM accounts_bak ;

INSERT INTO ids_temp (tbl, old_id, new_id)
SELECT 'client_registrations', id, client_id FROM client_registrations_bak ;

INSERT INTO ids_temp (tbl, old_id, new_id)
SELECT 'client_consent_logs', id, gen_random_uuid() FROM client_consent_logs_bak ;

-- publicate data
INSERT INTO accounts (id, creation_time)
SELECT ids.new_id, acc.creation_time
FROM accounts_bak acc
LEFT JOIN ids_temp ids
ON acc.id = ids.old_id
WHERE ids.tbl = 'accounts' ;

INSERT INTO account_federations (issuer, id_at_issuer, account_id)
SELECT fed.issuer, fed.id_at_issuer, ids.new_id
FROM account_federations_bak fed
LEFT JOIN ids_temp ids
ON fed.account_id = ids.old_id
WHERE ids.tbl = 'accounts' ;

INSERT INTO account_federation_sessions (id, issuer, id_at_issuer, creation_time, expiration_time)
SELECT id, issuer, id_at_issuer, creation_time, expiration_time
FROM account_federation_sessions_bak ;

INSERT INTO gw2_api_tokens (account_id, gw2_account_id, creation_time, gw2_api_token, gw2_api_permissions, display_name, last_valid_check_time, is_valid)
SELECT ids.new_id, tk.gw2_account_id, tk.creation_time, tk.gw2_api_token, tk.gw2_api_permissions, tk.display_name, tk.last_valid_check_time, tk.is_valid
FROM gw2_api_tokens_bak tk
LEFT JOIN ids_temp ids
ON tk.account_id = ids.old_id
WHERE ids.tbl = 'accounts' ;

INSERT INTO gw2_api_subtokens (account_id, gw2_account_id, gw2_api_permissions_bit_set, gw2_api_subtoken, expiration_time)
SELECT ids.new_id, tk.gw2_account_id, tk.gw2_api_permissions_bit_set, tk.gw2_api_subtoken, tk.expiration_time
FROM gw2_api_subtokens_bak tk
LEFT JOIN ids_temp ids
ON tk.account_id = ids.old_id
WHERE ids.tbl = 'accounts' ;

INSERT INTO gw2_account_verifications (gw2_account_id, account_id)
SELECT ver.gw2_account_id, ids.new_id
FROM gw2_account_verifications_bak ver
LEFT JOIN ids_temp ids
ON ver.account_id = ids.old_id
WHERE ids.tbl = 'accounts' ;

INSERT INTO gw2_account_verification_challenges (account_id, gw2_account_id, challenge_id, state, gw2_api_token, started_at, timeout_at)
SELECT ids.new_id, ch.gw2_account_id, ch.challenge_id, ch.state, ch.gw2_api_token, ch.started_at, ch.timeout_at
FROM gw2_account_verification_challenges_bak ch
LEFT JOIN ids_temp ids
ON ch.account_id = ids.old_id
WHERE ids.tbl = 'accounts' ;

INSERT INTO client_registrations (id, account_id, creation_time, display_name, client_secret, authorization_grant_types, redirect_uris)
SELECT reg.client_id, ids.new_id, reg.creation_time, reg.display_name, reg.client_secret, reg.authorization_grant_types, reg.redirect_uris
FROM client_registrations_bak reg
LEFT JOIN ids_temp ids
ON reg.account_id = ids.old_id
WHERE ids.tbl = 'accounts' ;

INSERT INTO client_consents (account_id, client_registration_id, account_sub, authorized_scopes)
SELECT acc_ids.new_id, reg_ids.new_id, cons.account_sub, cons.authorized_scopes
FROM client_consents_bak cons
LEFT JOIN ids_temp acc_ids
ON cons.account_id = acc_ids.old_id
LEFT JOIN ids_temp reg_ids
ON cons.client_registration_id = reg_ids.old_id
WHERE acc_ids.tbl = 'accounts'
AND reg_ids.tbl = 'client_registrations' ;

INSERT INTO client_consent_logs (id, account_id, client_registration_id, timestamp, type, messages)
SELECT log_ids.new_id, acc_ids.new_id, reg_ids.new_id, logs.timestamp, logs.type, logs.messages
FROM client_consent_logs_bak logs
LEFT JOIN ids_temp log_ids
ON logs.id = log_ids.old_id
LEFT JOIN ids_temp acc_ids
ON logs.account_id = acc_ids.old_id
LEFT JOIN ids_temp reg_ids
ON logs.client_registration_id = reg_ids.old_id
WHERE log_ids.tbl = 'client_consent_logs'
AND acc_ids.tbl = 'accounts'
AND reg_ids.tbl = 'client_registrations' ;

INSERT INTO client_authorizations (id, account_id, client_registration_id, creation_time, last_update_time, display_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at, authorization_code_metadata, access_token_value, access_token_issued_at, access_token_expires_at, access_token_metadata, access_token_type, access_token_scopes, refresh_token_value, refresh_token_issued_at, refresh_token_expires_at, refresh_token_metadata)
SELECT auth.id, acc_ids.new_id, reg_ids.new_id, auth.creation_time, auth.last_update_time, auth.display_name, auth.authorization_grant_type, auth.authorized_scopes, auth.attributes, auth.state, auth.authorization_code_value, auth.authorization_code_issued_at, auth.authorization_code_expires_at, auth.authorization_code_metadata, auth.access_token_value, auth.access_token_issued_at, auth.access_token_expires_at, auth.access_token_metadata, auth.access_token_type, auth.access_token_scopes, auth.refresh_token_value, auth.refresh_token_issued_at, auth.refresh_token_expires_at, auth.refresh_token_metadata
FROM client_authorizations_bak auth
LEFT JOIN ids_temp acc_ids
ON auth.account_id = acc_ids.old_id
LEFT JOIN ids_temp reg_ids
ON auth.client_registration_id = reg_ids.old_id
WHERE acc_ids.tbl = 'accounts'
AND reg_ids.tbl = 'client_registrations' ;

-- update old attributes to have the new uuid account id
UPDATE client_authorizations
SET attributes = jsonb_set(attributes::jsonb, '{"java.security.Principal", "principal", "accountId"}', to_jsonb(account_id::text), false)::text
WHERE (attributes::json->'java.security.Principal'->'principal'->'accountId') IS NOT NULL ;

UPDATE client_authorizations
SET attributes = jsonb_set(attributes::jsonb, '{"java.security.Principal", "user", "accountId"}', to_jsonb(account_id::text), false)::text
WHERE (attributes::json->'java.security.Principal'->'user'->'accountId') IS NOT NULL ;

INSERT INTO client_authorization_tokens (client_authorization_id, account_id, gw2_account_id)
SELECT tk.client_authorization_id, ids.new_id, tk.gw2_account_id
FROM client_authorization_tokens_bak tk
LEFT JOIN ids_temp ids
ON tk.account_id = ids.old_id
WHERE ids.tbl = 'accounts' ;

-- acls
GRANT ALL PRIVILEGES ON TABLE accounts TO gw2auth_app ;
GRANT ALL PRIVILEGES ON TABLE account_federations TO gw2auth_app ;
GRANT ALL PRIVILEGES ON TABLE account_federation_sessions TO gw2auth_app ;

GRANT ALL PRIVILEGES ON TABLE gw2_api_tokens TO gw2auth_app ;
GRANT ALL PRIVILEGES ON TABLE gw2_api_subtokens TO gw2auth_app ;
GRANT ALL PRIVILEGES ON TABLE gw2_account_verifications TO gw2auth_app ;
GRANT ALL PRIVILEGES ON TABLE gw2_account_verification_challenges TO gw2auth_app ;

GRANT ALL PRIVILEGES ON TABLE client_registrations TO gw2auth_app ;
GRANT ALL PRIVILEGES ON TABLE client_consents TO gw2auth_app ;
GRANT ALL PRIVILEGES ON TABLE client_consent_logs TO gw2auth_app ;
GRANT ALL PRIVILEGES ON TABLE client_authorizations TO gw2auth_app ;
GRANT ALL PRIVILEGES ON TABLE client_authorization_tokens TO gw2auth_app ;

-- drop bak tables
DROP TABLE ids_temp ;

DROP TABLE accounts_bak ;
DROP TABLE account_federations_bak ;
DROP TABLE account_federation_sessions_bak ;

DROP TABLE gw2_api_tokens_bak ;
DROP TABLE gw2_api_subtokens_bak ;
DROP TABLE gw2_account_verifications_bak ;
DROP TABLE gw2_account_verification_challenges_bak ;

DROP TABLE client_registrations_bak ;
DROP TABLE client_consents_bak ;
DROP TABLE client_consent_logs_bak ;
DROP TABLE client_authorizations_bak ;
DROP TABLE client_authorization_tokens_bak ;