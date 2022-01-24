ALTER TABLE client_registrations
DROP CONSTRAINT client_registrations_redirect_uri_check ;

ALTER TABLE client_registrations
ALTER COLUMN redirect_uri
TYPE TEXT[]
USING ARRAY[ redirect_uri ]::TEXT[] ;

ALTER TABLE client_registrations
RENAME redirect_uri TO redirect_uris ;

ALTER TABLE client_registrations
ADD CONSTRAINT client_registrations_redirect_uri_check
CHECK ( ARRAY_LENGTH(redirect_uris, 1) BETWEEN 1 AND 50 ) ;