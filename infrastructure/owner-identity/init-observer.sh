#!/bin/sh
set -eu
observer_password=$(cat /run/secrets/observer_password)
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 --set observer_password="$observer_password" <<'SQL'
SELECT format('CREATE ROLE oid_observer LOGIN PASSWORD %L', :'observer_password') \gexec
GRANT CONNECT ON DATABASE owner_identity TO oid_observer;
GRANT USAGE ON SCHEMA public TO oid_observer;
ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer;
ALTER ROLE oid_observer SET default_transaction_read_only = on;
SQL
unset observer_password
