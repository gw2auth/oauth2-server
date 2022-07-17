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

CREATE INDEX ON account_federations (account_id) ;

CREATE TABLE account_federation_sessions (
    id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    id_at_issuer TEXT NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    expiration_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (issuer, id_at_issuer) REFERENCES account_federations (issuer, id_at_issuer) ON DELETE CASCADE
) ;

CREATE TABLE account_logs (
    id UUID NOT NULL,
    account_id UUID NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    message TEXT NOT NULL,
    fields JSONB NOT NULL,
    persistent BOOLEAN NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ;

CREATE INDEX ON account_logs (account_id, timestamp) ;
CREATE INDEX ON account_logs USING GIN (account_id, fields) ;

CREATE TABLE gw2_api_tokens (
    account_id UUID NOT NULL,
    gw2_account_id UUID NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    gw2_api_token TEXT NOT NULL,
    gw2_api_permissions TEXT[] NOT NULL,
    display_name TEXT NOT NULL,
    last_valid_check_time TIMESTAMP WITH TIME ZONE NOT NULL,
    is_valid BOOLEAN NOT NULL,
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

CREATE INDEX ON gw2_account_verifications (account_id) ;

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

CREATE INDEX ON client_registrations (account_id) ;

CREATE TABLE client_consents (
    account_id UUID NOT NULL,
    client_registration_id UUID NOT NULL,
    account_sub UUID NOT NULL,
    authorized_scopes TEXT[] NOT NULL,
    PRIMARY KEY (account_id, client_registration_id),
    FOREIGN KEY (client_registration_id) REFERENCES client_registrations (id) ON DELETE CASCADE
) ;

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

CREATE INDEX ON client_authorizations (account_id, client_registration_id) ;

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

-- acls
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE accounts TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE account_federations TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE account_federation_sessions TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE account_logs TO gw2auth_app ;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE gw2_api_tokens TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE gw2_api_subtokens TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE gw2_account_verifications TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE gw2_account_verification_challenges TO gw2auth_app ;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE client_registrations TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE client_consents TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE client_authorizations TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE client_authorization_tokens TO gw2auth_app ;
