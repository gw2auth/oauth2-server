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

-- migrate existing logs
INSERT INTO account_logs (id, account_id, timestamp, message, fields, persistent)
SELECT gen_random_uuid(), account_id, timestamp, unnest(messages), jsonb_build_object('type', type, 'client_id', client_registration_id), FALSE
FROM client_consent_logs ;

-- drop old table
DROP TABLE client_consent_logs ;

-- indexes
CREATE INDEX ON account_logs (timestamp) ;
CREATE INDEX ON account_logs USING GIN (fields) ;

-- acls
GRANT ALL PRIVILEGES ON TABLE account_logs TO gw2auth_app ;