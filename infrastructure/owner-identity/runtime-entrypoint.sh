#!/bin/sh
set -eu
if [ -f /run/secrets/owner_password ]; then
  oid_password=$(cat /run/secrets/owner_password)
  export OID_DATABASE_URL="postgres://oid_owner:${oid_password}@postgres:5432/owner_identity"
  unset oid_password
fi
if [ -f /run/secrets/observer_password ]; then
  oid_observer_password=$(cat /run/secrets/observer_password)
  export OID_OBSERVER_DATABASE_URL="postgres://oid_observer:${oid_observer_password}@postgres:5432/owner_identity"
  unset oid_observer_password
fi
if [ -f /run/secrets/auth_secret ]; then
  export OID_AUTH_SECRET="$(cat /run/secrets/auth_secret)"
fi
exec "$@"
