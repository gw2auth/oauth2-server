CREATE TABLE client_authorization_logs_bak AS SELECT * FROM client_authorization_logs ;

DROP TABLE client_authorization_logs ;

CREATE TABLE client_authorization_logs (
    id BIGSERIAL NOT NULL,
    account_id BIGINT NOT NULL,
    client_registration_id BIGINT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    type VARCHAR NOT NULL,
    messages VARCHAR[] NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (account_id, client_registration_id) REFERENCES client_authorizations (account_id, client_registration_id) ON DELETE CASCADE
) ;

INSERT INTO client_authorization_logs
(account_id, client_registration_id, timestamp, type, messages)
SELECT account_id, client_registration_id, timestamp, 'ACCESS_TOKEN', messages
FROM client_authorization_logs_bak ;

DROP TABLE client_authorization_logs_bak ;

CREATE INDEX ON client_authorization_logs USING BRIN ( account_id, client_registration_id, timestamp ) ;