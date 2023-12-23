CREATE TABLE application_api_keys (
    id UUID NOT NULL,
    application_id UUID NOT NULL,
    key TEXT NOT NULL,
    permissions TEXT[] NOT NULL,
    not_before TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (id),
    FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
    UNIQUE (key)
) ;

-- acls
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE application_api_keys TO gw2auth_app ;