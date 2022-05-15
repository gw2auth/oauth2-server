DO
$do$
    BEGIN
        IF NOT EXISTS ( SELECT FROM pg_catalog.pg_roles WHERE rolname = 'gw2auth_app' ) THEN
            CREATE ROLE gw2auth_app ;
        END IF;
    END
$do$;

GRANT CONNECT ON DATABASE postgres TO gw2auth_app ;
GRANT ALL PRIVILEGES ON TABLE client_authorizations TO gw2auth_app;
GRANT ALL PRIVILEGES ON TABLE gw2_api_tokens TO gw2auth_app;
GRANT ALL PRIVILEGES ON TABLE client_consents TO gw2auth_app;
GRANT ALL PRIVILEGES ON TABLE client_registrations TO gw2auth_app;
GRANT ALL PRIVILEGES ON TABLE client_consent_logs TO gw2auth_app;
GRANT ALL PRIVILEGES ON TABLE gw2_account_verification_challenges TO gw2auth_app;
GRANT ALL PRIVILEGES ON TABLE gw2_account_verifications TO gw2auth_app;
GRANT ALL PRIVILEGES ON TABLE gw2_api_subtokens TO gw2auth_app;
GRANT ALL PRIVILEGES ON TABLE client_authorization_tokens TO gw2auth_app;
GRANT ALL PRIVILEGES ON TABLE accounts TO gw2auth_app;
GRANT ALL PRIVILEGES ON TABLE account_federations TO gw2auth_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO gw2auth_app ;