CREATE TABLE accounts (
    id BIGSERIAL NOT NULL,
    creation_time TIMESTAMP NOT NULL,
    PRIMARY KEY (id)
) ;

CREATE TABLE account_federations (
    issuer VARCHAR NOT NULL,
    id_at_issuer VARCHAR NOT NULL,
    account_id BIGINT NOT NULL,
    PRIMARY KEY (issuer, id_at_issuer),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ;

CREATE TABLE gw2_api_tokens (
    account_id BIGINT NOT NULL,
    gw2_account_id VARCHAR NOT NULL,
    creation_time TIMESTAMP NOT NULL,
    gw2_api_token VARCHAR NOT NULL,
    gw2_api_permissions VARCHAR[] NOT NULL,
    display_name VARCHAR NOT NULL,
    PRIMARY KEY (account_id, gw2_account_id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
    CHECK ( LENGTH(display_name) > 0 AND LENGTH(display_name) <= 100 )
) ;

CREATE TABLE gw2_account_verification_challenges (
    account_id BIGINT NOT NULL,
    gw2_account_id VARCHAR NOT NULL,
    challenge_id BIGINT NOT NULL,
    state_class VARCHAR NOT NULL,
    state VARCHAR NOT NULL,
    gw2_api_token VARCHAR,
    started_at TIMESTAMP,
    timeout_at TIMESTAMP,
    PRIMARY KEY (account_id, gw2_account_id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ;

CREATE TABLE gw2_account_verifications (
    gw2_account_id VARCHAR NOT NULL,
    account_id BIGINT NOT NULL,
    PRIMARY KEY (gw2_account_id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ;

CREATE TABLE client_registrations (
    id BIGSERIAL NOT NULL,
    account_id BIGINT NOT NULL,
    creation_time TIMESTAMP NOT NULL,
    display_name VARCHAR NOT NULL,
    client_id VARCHAR NOT NULL,
    client_secret VARCHAR NOT NULL,
    authorization_grant_types VARCHAR[] NOT NULL,
    redirect_uri VARCHAR NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (client_id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
    CHECK ( LENGTH(display_name) > 0 AND LENGTH(display_name) <= 100 ),
    CHECK ( LENGTH(redirect_uri) >= 8 AND LENGTH(redirect_uri) <= 1000 ) -- 'http://a' is the shortest possible redirectUri (8 chars)
) ;

CREATE TABLE client_authorizations (
    account_id BIGINT NOT NULL,
    client_registration_id BIGINT NOT NULL,
    account_sub UUID NOT NULL,
    authorized_scopes VARCHAR[] NOT NULL,
    PRIMARY KEY (account_id, client_registration_id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
    FOREIGN KEY (client_registration_id) REFERENCES client_registrations (id) ON DELETE CASCADE
) ;

CREATE TABLE client_authorization_tokens (
    account_id BIGINT NOT NULL,
    client_registration_id BIGINT NOT NULL,
    gw2_account_id VARCHAR NOT NULL,
    gw2_api_subtoken VARCHAR NOT NULL,
    expiration_time TIMESTAMP NOT NULL,
    PRIMARY KEY (account_id, client_registration_id, gw2_account_id),
    FOREIGN KEY (account_id, client_registration_id) REFERENCES client_authorizations (account_id, client_registration_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_api_tokens (account_id, gw2_account_id) ON DELETE CASCADE
) ;

CREATE TABLE client_authorization_logs (
    id BIGSERIAL NOT NULL,
    account_id BIGINT NOT NULL,
    client_registration_id BIGINT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    messages VARCHAR[] NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (account_id, client_registration_id) REFERENCES client_authorizations (account_id, client_registration_id) ON DELETE CASCADE
) ;

CREATE INDEX ON client_authorization_logs USING BRIN ( account_id, client_registration_id, timestamp ) ;

CREATE TABLE oauth2_authorization (
    account_id BIGINT NOT NULL,
    client_registration_id BIGINT NOT NULL,
    id VARCHAR NOT NULL, -- only keep this for spring integration
    authorization_grant_type VARCHAR NOT NULL,
    attributes VARCHAR DEFAULT NULL,
    state VARCHAR DEFAULT NULL,
    authorization_code_value BYTEA DEFAULT NULL,
    authorization_code_issued_at TIMESTAMP DEFAULT NULL,
    authorization_code_expires_at TIMESTAMP DEFAULT NULL,
    authorization_code_metadata VARCHAR DEFAULT NULL,
    access_token_value BYTEA DEFAULT NULL,
    access_token_issued_at TIMESTAMP DEFAULT NULL,
    access_token_expires_at TIMESTAMP DEFAULT NULL,
    access_token_metadata VARCHAR DEFAULT NULL,
    access_token_type VARCHAR DEFAULT NULL,
    access_token_scopes VARCHAR[] DEFAULT NULL,
    refresh_token_value BYTEA DEFAULT NULL,
    refresh_token_issued_at TIMESTAMP DEFAULT NULL,
    refresh_token_expires_at TIMESTAMP DEFAULT NULL,
    refresh_token_metadata VARCHAR DEFAULT NULL,
    PRIMARY KEY (account_id, client_registration_id),
    FOREIGN KEY (account_id, client_registration_id) REFERENCES client_authorizations (account_id, client_registration_id) ON DELETE CASCADE
);