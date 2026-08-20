CREATE TABLE account_registry (
    id UUID NOT NULL,
    deletion_time TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (id)
) ;

INSERT INTO account_registry
(id, deletion_time)
SELECT id, NULL
FROM accounts ;

INSERT INTO account_registry
(id, deletion_time)
SELECT DISTINCT account_subs.account_id, '1970-01-01 00:00:00+00'::TIMESTAMP WITH TIME ZONE
FROM application_account_subs account_subs
LEFT JOIN accounts
ON account_subs.account_id = accounts.id
WHERE accounts.id IS NULL ;

CREATE INDEX ON account_registry (deletion_time)
WHERE deletion_time IS NOT NULL ;

ALTER TABLE application_account_subs
ADD CONSTRAINT application_account_subs_account_registry_fk
FOREIGN KEY (account_id) REFERENCES account_registry (id) ;

ALTER TABLE accounts
ADD CONSTRAINT accounts_account_registry_fk
FOREIGN KEY (id) REFERENCES account_registry (id) ;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE account_registry TO gw2auth_app ;
