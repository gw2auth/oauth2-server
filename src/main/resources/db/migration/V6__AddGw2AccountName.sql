ALTER TABLE gw2_accounts
ADD COLUMN gw2_account_name TEXT ;

UPDATE gw2_accounts
SET gw2_account_name = display_name ;

ALTER TABLE gw2_accounts
ALTER COLUMN gw2_account_name SET NOT NULL ;