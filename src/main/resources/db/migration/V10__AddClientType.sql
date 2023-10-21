ALTER TABLE application_clients
ADD COLUMN type TEXT ;

UPDATE application_clients
SET type = 'CONFIDENTIAL' ;

ALTER TABLE application_clients
ALTER COLUMN type SET NOT NULL ;

ALTER TABLE application_clients
ALTER COLUMN client_secret DROP NOT NULL ;