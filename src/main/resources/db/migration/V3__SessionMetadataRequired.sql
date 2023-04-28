DELETE FROM account_federation_sessions
WHERE metadata IS NULL ;

ALTER TABLE account_federation_sessions
ALTER COLUMN metadata SET NOT NULL ;