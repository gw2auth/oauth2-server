CREATE INDEX ON client_authorizations USING HASH ( authorization_code_value ) ;
CREATE INDEX ON client_authorizations USING HASH ( access_token_value ) ;
CREATE INDEX ON client_authorizations USING HASH ( refresh_token_value ) ;