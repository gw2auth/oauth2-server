CREATE TABLE temp_gw2_account_verifications
AS SELECT * FROM gw2_account_verifications ;

DROP TABLE gw2_account_verifications ;

CREATE TABLE gw2_accounts (
    account_id UUID NOT NULL,
    gw2_account_id UUID NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    display_name TEXT NOT NULL,
    order_rank TEXT NOT NULL,
    PRIMARY KEY (account_id, gw2_account_id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
    CHECK ( LENGTH(display_name) BETWEEN 1 AND 100 )
) ;

CREATE TABLE gw2_account_verifications (
    gw2_account_id UUID NOT NULL,
    account_id UUID NOT NULL,
    PRIMARY KEY (gw2_account_id),
    FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_accounts (account_id, gw2_account_id) ON DELETE CASCADE
) ;

CREATE TABLE gw2_account_api_tokens (
    account_id UUID NOT NULL,
    gw2_account_id UUID NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    gw2_api_token TEXT NOT NULL,
    gw2_api_permissions_bit_set INT NOT NULL,
    last_valid_time TIMESTAMP WITH TIME ZONE NOT NULL,
    last_valid_check_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (account_id, gw2_account_id),
    FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_accounts (account_id, gw2_account_id) ON DELETE CASCADE
) ;

CREATE TABLE gw2_account_api_subtokens (
    account_id UUID NOT NULL,
    gw2_account_id UUID NOT NULL,
    gw2_api_permissions_bit_set INT NOT NULL,
    gw2_api_subtoken TEXT NOT NULL,
    expiration_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (account_id, gw2_account_id, gw2_api_permissions_bit_set),
    FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_account_api_tokens (account_id, gw2_account_id) ON DELETE CASCADE
) ;

-- populate tables
INSERT INTO gw2_accounts
(account_id, gw2_account_id, creation_time, display_name, order_rank)
SELECT account_id, gw2_account_id, creation_time, display_name, 'A'
FROM gw2_api_tokens ;

INSERT INTO gw2_accounts
(account_id, gw2_account_id, creation_time, display_name, order_rank)
SELECT account_id, gw2_account_id, CURRENT_TIMESTAMP, gw2_account_id, 'A'
FROM temp_gw2_account_verifications
ON CONFLICT (account_id, gw2_account_id) DO NOTHING ;

INSERT INTO gw2_account_verifications
(gw2_account_id, account_id)
SELECT gw2_account_id, account_id
FROM temp_gw2_account_verifications ;

DROP TABLE temp_gw2_account_verifications ;

INSERT INTO gw2_account_api_tokens
(account_id, gw2_account_id, creation_time, gw2_api_token, gw2_api_permissions_bit_set, last_valid_time, last_valid_check_time)
SELECT
    account_id,
    gw2_account_id,
    MAX(creation_time),
    MAX(gw2_api_token),
    BIT_OR(
        CASE
            WHEN gw2_api_permission = 'account' THEN 1 << 0
            WHEN gw2_api_permission = 'builds' THEN 1 << 1
            WHEN gw2_api_permission = 'characters' THEN 1 << 2
            WHEN gw2_api_permission = 'guilds' THEN 1 << 3
            WHEN gw2_api_permission = 'inventories' THEN 1 << 4
            WHEN gw2_api_permission = 'progression' THEN 1 << 5
            WHEN gw2_api_permission = 'pvp' THEN 1 << 6
            WHEN gw2_api_permission = 'tradingpost' THEN 1 << 7
            WHEN gw2_api_permission = 'unlocks' THEN 1 << 8
            WHEN gw2_api_permission = 'wallet' THEN 1 << 9
            ELSE 0
        END
    ) AS gw2_api_permissions_bit_set,
    MAX(last_valid_check_time),
    MAX(last_valid_check_time)
FROM (
    SELECT
        account_id,
        gw2_account_id,
        creation_time,
        gw2_api_token,
        UNNEST(gw2_api_permissions) AS gw2_api_permission,
        last_valid_check_time
    FROM gw2_api_tokens
) as sub
GROUP BY account_id, gw2_account_id ;

INSERT INTO gw2_account_api_subtokens
(account_id, gw2_account_id, gw2_api_permissions_bit_set, gw2_api_subtoken, expiration_time)
SELECT account_id, gw2_account_id, gw2_api_permissions_bit_set, gw2_api_subtoken, expiration_time
FROM gw2_api_subtokens ;

-- indexes
CREATE INDEX ON gw2_account_api_tokens (last_valid_time) ;
CREATE INDEX ON gw2_account_api_tokens (last_valid_check_time) ;

-- acls
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE gw2_accounts TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE gw2_account_verifications TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE gw2_account_api_tokens TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE gw2_account_api_subtokens TO gw2auth_app ;

-- oauth2 tables
CREATE TABLE applications (
    id UUID NOT NULL,
    account_id UUID NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    display_name TEXT NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
    CHECK ( LENGTH(display_name) BETWEEN 1 AND 100 )
) ;

-- to not reuse account_sub even if the original user deleted their account
CREATE TABLE application_account_subs (
    application_id UUID NOT NULL,
    account_id UUID NOT NULL,
    account_sub UUID NOT NULL,
    PRIMARY KEY (application_id, account_id),
    FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
    -- no foreign key on accounts here - this should be kept alive even if the account is deleted
    UNIQUE (application_id, account_sub)
) ;

CREATE TABLE application_accounts (
    application_id UUID NOT NULL,
    account_id UUID NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (application_id, account_id),
    FOREIGN KEY (application_id, account_id) REFERENCES application_account_subs (application_id, account_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ;

CREATE TABLE application_clients (
    id UUID NOT NULL,
    application_id UUID NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    display_name TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    authorization_grant_types TEXT[] NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    requires_approval BOOLEAN NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
    CHECK ( LENGTH(display_name) BETWEEN 1 AND 100 ),
    CHECK ( ARRAY_LENGTH(redirect_uris, 1) BETWEEN 1 AND 50 )
) ;

CREATE TABLE application_client_accounts (
    application_client_id UUID NOT NULL,
    account_id UUID NOT NULL,
    application_id UUID NOT NULL,
    approval_status TEXT NOT NULL,
    approval_request_message TEXT NOT NULL,
    authorized_scopes TEXT[] NOT NULL,
    PRIMARY KEY (application_client_id, account_id),
    FOREIGN KEY (application_client_id) REFERENCES application_clients (id) ON DELETE CASCADE,
    FOREIGN KEY (application_id, account_id) REFERENCES application_accounts (application_id, account_id) ON DELETE CASCADE
) ;

CREATE TABLE application_client_authorizations (
    id TEXT NOT NULL,
    account_id UUID NOT NULL,
    application_client_id UUID NOT NULL,
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
    FOREIGN KEY (account_id, application_client_id) REFERENCES application_client_accounts (account_id, application_client_id) ON DELETE CASCADE,
    UNIQUE (state)
) ;

CREATE TABLE application_client_authorization_gw2_accounts (
    application_client_authorization_id TEXT NOT NULL,
    account_id UUID NOT NULL,
    gw2_account_id UUID NOT NULL,
    PRIMARY KEY (application_client_authorization_id, gw2_account_id),
    FOREIGN KEY (application_client_authorization_id) REFERENCES application_client_authorizations (id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, gw2_account_id) REFERENCES gw2_accounts (account_id, gw2_account_id) ON DELETE CASCADE
) ;

-- populate tables
CREATE TABLE temp_client_registrations
AS SELECT gen_random_uuid() AS application_id, *
FROM client_registrations ;

INSERT INTO applications
(id, account_id, creation_time, display_name)
SELECT application_id, account_id, creation_time, display_name
FROM temp_client_registrations ;

INSERT INTO application_account_subs
(application_id, account_id, account_sub)
SELECT reg.application_id, cons.account_id, cons.account_sub
FROM client_consents cons
INNER JOIN temp_client_registrations reg
ON cons.client_registration_id = reg.id ;

INSERT INTO application_accounts
(application_id, account_id, creation_time)
SELECT reg.application_id, cons.account_id, COALESCE(MIN(auth.creation_time), CURRENT_TIMESTAMP)
FROM client_consents cons
INNER JOIN accounts acc
ON cons.account_id = acc.id
INNER JOIN temp_client_registrations reg
ON cons.client_registration_id = reg.id
LEFT JOIN client_authorizations auth
ON cons.client_registration_id = auth.client_registration_id AND cons.account_id = auth.account_id
GROUP BY reg.application_id, cons.account_id ;

INSERT INTO application_clients
(id, application_id, creation_time, display_name, client_secret, authorization_grant_types, redirect_uris, requires_approval)
SELECT id, application_id, creation_time, display_name, client_secret, authorization_grant_types, redirect_uris, FALSE
FROM temp_client_registrations ;

INSERT INTO application_client_accounts
(application_client_id, account_id, application_id, approval_status, approval_request_message, authorized_scopes)
SELECT cons.client_registration_id, cons.account_id, reg.application_id, 'APPROVED', 'GW2AUTH_MIGRATION', cons.authorized_scopes
FROM client_consents cons
INNER JOIN accounts acc
ON cons.account_id = acc.id
INNER JOIN temp_client_registrations reg
ON cons.client_registration_id = reg.id ;

INSERT INTO application_client_authorizations
(id, account_id, application_client_id, creation_time, last_update_time, display_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at, authorization_code_metadata, access_token_value, access_token_issued_at, access_token_expires_at, access_token_metadata, access_token_type, access_token_scopes, refresh_token_value, refresh_token_issued_at, refresh_token_expires_at, refresh_token_metadata)
SELECT
    auth.id,
    auth.account_id,
    auth.client_registration_id,
    auth.creation_time,
    auth.last_update_time,
    auth.display_name,
    auth.authorization_grant_type,
    auth.authorized_scopes,
    auth.attributes,
    auth.state,
    auth.authorization_code_value,
    auth.authorization_code_issued_at,
    auth.authorization_code_expires_at,
    auth.authorization_code_metadata,
    auth.access_token_value,
    auth.access_token_issued_at,
    auth.access_token_expires_at,
    auth.access_token_metadata,
    auth.access_token_type,
    auth.access_token_scopes,
    auth.refresh_token_value,
    auth.refresh_token_issued_at,
    auth.refresh_token_expires_at,
    auth.refresh_token_metadata
FROM client_authorizations auth
INNER JOIN accounts acc
ON auth.account_id = acc.id ;

INSERT INTO application_client_authorization_gw2_accounts
(application_client_authorization_id, account_id, gw2_account_id)
SELECT client_authorization_id, account_id, gw2_account_id
FROM client_authorization_tokens ;

DROP TABLE temp_client_registrations ;

-- indexes
CREATE INDEX ON applications (account_id) ;
CREATE INDEX ON application_accounts (application_id) ;
CREATE INDEX ON application_clients (application_id) ;
CREATE INDEX ON application_client_accounts (application_client_id) ;
CREATE INDEX ON application_client_authorizations (account_id, application_client_id) ;

-- these columns are too large for a normal index, use hashed index
-- (no strong crypto requirements, thus using md5 instead of sha)
CREATE INDEX ON application_client_authorizations (md5(authorization_code_value)) ;
CREATE INDEX ON application_client_authorizations (md5(access_token_value)) ;
CREATE INDEX ON application_client_authorizations (md5(refresh_token_value)) ;

-- drop old tables
DROP TABLE client_authorization_tokens ;
DROP TABLE client_authorizations ;
DROP TABLE client_consents ;
DROP TABLE client_registrations ;

DROP TABLE gw2_api_subtokens ;
DROP TABLE gw2_api_tokens ;

-- acls
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE applications TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE application_account_subs TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE application_accounts TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE application_clients TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE application_client_accounts TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE application_client_authorizations TO gw2auth_app ;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE application_client_authorization_gw2_accounts TO gw2auth_app ;