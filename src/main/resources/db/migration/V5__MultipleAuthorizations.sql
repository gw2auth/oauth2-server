-- create backups
CREATE TABLE client_authorizations_bak AS SELECT * FROM client_authorizations ;
CREATE TABLE client_authorization_logs_bak AS SELECT * FROM client_authorization_logs ;
CREATE TABLE oauth2_authorization_bak AS SELECT * FROM oauth2_authorization ;
CREATE TABLE client_authorization_tokens_bak AS SELECT * FROM client_authorization_tokens ;

-- drop old tables
DROP TABLE oauth2_authorization ;
DROP TABLE client_authorization_logs ;
DROP TABLE client_authorization_tokens ;
DROP TABLE client_authorizations ;

-- create new tables
CREATE TABLE gw2_api_subtokens (
    account_id BIGINT NOT NULL,
    gw2_account_id VARCHAR NOT NULL,
    gw2_api_permissions_bit_set INT NOT NULL,
    gw2_api_subtoken VARCHAR NOT NULL,
    expiration_time TIMESTAMP NOT NULL,
    PRIMARY KEY (account_id, gw2_account_id, gw2_api_permissions_bit_set),
    FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_api_tokens (account_id, gw2_account_id) ON DELETE CASCADE
) ;

CREATE TABLE client_consents (
    account_id BIGINT NOT NULL,
    client_registration_id BIGINT NOT NULL,
    account_sub UUID NOT NULL,
    authorized_scopes VARCHAR[] NOT NULL,
    PRIMARY KEY (account_id, client_registration_id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
    FOREIGN KEY (client_registration_id) REFERENCES client_registrations (id) ON DELETE CASCADE
) ;

CREATE TABLE client_consent_logs (
    id BIGSERIAL NOT NULL,
    account_id BIGINT NOT NULL,
    client_registration_id BIGINT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    type VARCHAR NOT NULL,
    messages VARCHAR[] NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (account_id, client_registration_id) REFERENCES client_consents (account_id, client_registration_id) ON DELETE CASCADE
) ;

CREATE INDEX ON client_consent_logs USING BRIN ( account_id, client_registration_id, timestamp ) ;

CREATE TABLE client_authorizations (
    account_id BIGINT NOT NULL,
    id VARCHAR NOT NULL,
    client_registration_id BIGINT NOT NULL,
    creation_time TIMESTAMP NOT NULL,
    last_update_time TIMESTAMP NOT NULL,
    display_name VARCHAR NOT NULL,
    authorization_grant_type VARCHAR NOT NULL,
    authorized_scopes VARCHAR[] NOT NULL,
    attributes VARCHAR,
    state VARCHAR,
    authorization_code_value VARCHAR,
    authorization_code_issued_at TIMESTAMP,
    authorization_code_expires_at TIMESTAMP,
    authorization_code_metadata VARCHAR,
    access_token_value VARCHAR,
    access_token_issued_at TIMESTAMP,
    access_token_expires_at TIMESTAMP,
    access_token_metadata VARCHAR,
    access_token_type VARCHAR,
    access_token_scopes VARCHAR[] NOT NULL,
    refresh_token_value VARCHAR,
    refresh_token_issued_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    refresh_token_metadata VARCHAR,
    PRIMARY KEY (account_id, id),
    FOREIGN KEY (account_id, client_registration_id) REFERENCES client_consents (account_id, client_registration_id) ON DELETE CASCADE,
    UNIQUE (state),
    UNIQUE (authorization_code_value),
    UNIQUE (access_token_value),
    UNIQUE (refresh_token_value),
    CHECK ( LENGTH(display_name) > 0 AND LENGTH(display_name) <= 100 )
) ;

CREATE TABLE client_authorization_tokens (
    account_id BIGINT NOT NULL,
    client_authorization_id VARCHAR NOT NULL,
    gw2_account_id VARCHAR NOT NULL,
    PRIMARY KEY (account_id, client_authorization_id, gw2_account_id),
    FOREIGN KEY (account_id, client_authorization_id) REFERENCES client_authorizations (account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_api_tokens (account_id, gw2_account_id) ON DELETE CASCADE
) ;

-- populate data to new tables
INSERT INTO client_consents
(account_id, client_registration_id, account_sub, authorized_scopes)
SELECT account_id, client_registration_id, account_sub, authorized_scopes
FROM client_authorizations_bak ;

INSERT INTO client_consent_logs
(account_id, client_registration_id, timestamp, type, messages)
SELECT account_id, client_registration_id, timestamp, type, messages
FROM client_authorization_logs_bak ;

INSERT INTO client_authorizations
(account_id, id, client_registration_id, creation_time, last_update_time, display_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at, authorization_code_metadata, access_token_value, access_token_issued_at, access_token_expires_at, access_token_metadata, access_token_type, access_token_scopes, refresh_token_value, refresh_token_issued_at, refresh_token_expires_at, refresh_token_metadata)
SELECT account_id, id, client_registration_id, COALESCE(access_token_issued_at, NOW()), COALESCE(access_token_issued_at, NOW()), id, authorization_grant_type, COALESCE(access_token_scopes, ARRAY[]::VARCHAR[]), attributes, state, convert_from(authorization_code_value, 'UTF-8'), authorization_code_issued_at, authorization_code_expires_at, authorization_code_metadata, convert_from(access_token_value, 'UTF-8'), access_token_issued_at, access_token_expires_at, access_token_metadata, access_token_type, COALESCE(access_token_scopes, ARRAY[]::VARCHAR[]), convert_from(refresh_token_value, 'UTF-8'), refresh_token_issued_at, refresh_token_expires_at, refresh_token_metadata
FROM oauth2_authorization_bak ;

INSERT INTO client_authorization_tokens
(account_id, client_authorization_id, gw2_account_id)
SELECT tokens.account_id, oauth2.id, tokens.gw2_account_id
FROM client_authorization_tokens_bak tokens
INNER JOIN client_authorizations_bak auth
ON tokens.account_id = auth.account_id AND tokens.client_registration_id = auth.client_registration_id
INNER JOIN oauth2_authorization_bak oauth2
ON auth.account_id = oauth2.account_id AND auth.client_registration_id = oauth2.client_registration_id ;

-- dont insert anything into gw2_api_subtokens -> after releasing this version, let the application initially create new ones

-- drop backup tables
DROP TABLE client_authorizations_bak ;
DROP TABLE client_authorization_logs_bak ;
DROP TABLE oauth2_authorization_bak ;
DROP TABLE client_authorization_tokens_bak ;