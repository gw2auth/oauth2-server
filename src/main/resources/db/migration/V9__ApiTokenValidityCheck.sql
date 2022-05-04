ALTER TABLE gw2_api_tokens
ADD COLUMN last_valid_check_time TIMESTAMP,
ADD COLUMN is_valid BOOLEAN ;

UPDATE gw2_api_tokens
SET last_valid_check_time = creation_time, is_valid = TRUE ;

ALTER TABLE gw2_api_tokens
ALTER COLUMN last_valid_check_time SET NOT NULL,
ALTER COLUMN is_valid SET NOT NULL ;

CREATE INDEX ON gw2_api_tokens USING BRIN ( last_valid_check_time ) ;