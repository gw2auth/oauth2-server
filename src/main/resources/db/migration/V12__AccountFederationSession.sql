CREATE TABLE account_federation_sessions (
    id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    id_at_issuer TEXT NOT NULL,
    creation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    expiration_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (issuer, id_at_issuer) REFERENCES account_federations (issuer, id_at_issuer) ON DELETE CASCADE
) ;

GRANT ALL PRIVILEGES ON TABLE account_federation_sessions TO gw2auth_app;