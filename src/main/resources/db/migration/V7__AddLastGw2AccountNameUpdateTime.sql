ALTER TABLE gw2_accounts
ADD COLUMN last_name_check_time TIMESTAMP WITH TIME ZONE;

UPDATE gw2_accounts
SET last_name_check_time = NOW() - INTERVAL '1' DAY;

ALTER TABLE gw2_accounts
ALTER COLUMN last_name_check_time SET NOT NULL ;