ALTER TABLE application_clients
ADD COLUMN api_version INT ;

UPDATE application_clients
SET api_version = 0 ;

ALTER TABLE application_clients
ALTER COLUMN api_version SET NOT NULL ;