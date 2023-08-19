ALTER TABLE gw2_accounts
    ADD COLUMN last_name_check_time TIMESTAMP WITH TIME ZONE;

UPDATE gw2_accounts
SET last_name_check_time = tk.last_valid_time
FROM gw2_accounts acc
INNER JOIN gw2_account_api_tokens tk
ON tk.account_id = acc.account_id AND tk.gw2_account_id = acc.gw2_account_id;

ALTER TABLE gw2_accounts
    ALTER COLUMN last_name_check_time SET NOT NULL ;