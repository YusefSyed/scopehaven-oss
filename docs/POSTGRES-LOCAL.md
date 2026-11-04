# Trying the observers against a local Postgres

This is a disposable, synthetic database, not an application database. Run these commands from the repository root on macOS or Linux with Docker running and the pinned Node.js 24.22.2 available (see [CONTRIBUTING.md](../CONTRIBUTING.md)). No npm install is needed. All client addresses and published ports stay on `127.0.0.1`.

## Start the server

The name and port below must be unused. The passwords are examples for this disposable database only. No host directory or named volume is mounted.

```sh
docker run --rm -d --name scopehaven-postgres-local \
  --cpus 1 --memory 512m \
  -p 127.0.0.1:55432:5432 \
  -e POSTGRES_USER=scopehaven_admin \
  -e POSTGRES_PASSWORD=local-test-admin \
  -e POSTGRES_DB=scopehaven \
  -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
  postgres:17-alpine -c wal_level=logical

(
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if docker exec scopehaven-postgres-local pg_isready -h 127.0.0.1 -p 5432 -U scopehaven_admin -d scopehaven; then
      docker exec scopehaven-postgres-local psql -X -U scopehaven_admin -d scopehaven -c 'SELECT version(); SHOW wal_level;'
      exit $?
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  docker logs scopehaven-postgres-local
  printf '%s\n' 'Postgres did not become ready on TCP within 30 attempts; stop here and inspect the logs.' >&2
  exit 1
)
```

The TCP probe waits for the final server, not its temporary socket-only initialization server. If `docker run` or the readiness block fails, do not continue to the role or test commands. Inspect the logs, use the cleanup below to remove this disposable container, and resolve the error before starting again.

`wal_level=logical` also permits the [pg-wal live tests](PG-WAL.md#tests). The built-in wire client requires SCRAM-SHA-256; do not replace the host authentication method with `trust` or `md5`.

## Separate the test administrator from observer credentials

`scopehaven_admin` is the bootstrap superuser of this disposable server. `pg.live.test.mjs` needs to create tables and roles, and exercises operations such as extensions and vacuum. `pg-wal.live.test.mjs` uses the same administrator connection to create its own temporary test roles, including a `REPLICATION` reader. Neither suite should run against a database you need to keep.

For a profile example, create a synthetic table and separate reader roles:

```sh
docker exec -i scopehaven-postgres-local psql -X -v ON_ERROR_STOP=1 -U scopehaven_admin -d scopehaven <<'SQL'
CREATE TABLE public.scopehaven_demo (id text PRIMARY KEY, value text);
INSERT INTO public.scopehaven_demo VALUES ('one', 'synthetic');
CREATE ROLE scopehaven_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD 'local-test-reader';
CREATE ROLE scopehaven_wal LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE REPLICATION PASSWORD 'local-test-wal';
GRANT CONNECT ON DATABASE scopehaven TO scopehaven_reader, scopehaven_wal;
GRANT USAGE ON SCHEMA public TO scopehaven_reader;
GRANT SELECT ON public.scopehaven_demo TO scopehaven_reader;
SQL
```

The snapshot reader has `SELECT` only on the declared table, with no write grant. The separate WAL role has `REPLICATION`, which can expose changes beyond one table; it is not the snapshot reader. The live tests create and drop their own randomly named roles rather than using these two profile-example roles.

## Run a live test

```sh
export SCOPEHAVEN_PG_LIVE='scopehaven_admin:local-test-admin@127.0.0.1:55432/scopehaven'
node --test integrations/observers/pg.live.test.mjs
```

The suite creates and removes its own tables and roles. It includes a role without `SELECT`, which must fail the observation rather than report an empty successful window. To also exercise logical decoding on this server:

```sh
node --test integrations/observers/pg-wal.live.test.mjs
```

One WAL test intentionally skips unless `SCOPEHAVEN_PG_LIVE_ALTER_SYSTEM=1`: it changes a server setting. Leave that variable unset for this walkthrough.

## Use the SELECT-only role in a profile

Set the credential in the shell that runs your profile; it is `user:password`, without a host or database:

```sh
export SCOPEHAVEN_TARGET_LOCAL_PG_READER='scopehaven_reader:local-test-reader'
```

Add this entry to the profile's `observers` array (the rest of a profile is described in [Onboarding](ONBOARDING.md#observe-what-the-app-recorded-the-default)):

```json
{
  "id": "local-db",
  "type": "pg-snapshot",
  "host": "127.0.0.1",
  "port": 55432,
  "database": "scopehaven",
  "credentialEnv": "SCOPEHAVEN_TARGET_LOCAL_PG_READER",
  "tables": [{ "table": "scopehaven_demo", "key": "id" }]
}
```

Do not use the test administrator or the replication role as the snapshot observer's credential. Snapshot inserts and deletes are net-only: a row inserted and deleted between marks is not seen. See the [observer's limits](../integrations/observers/README.md#postgres-snapshot-observer-pg-snapshot), including custody, before interpreting a profile result.

## Clean up

```sh
unset SCOPEHAVEN_PG_LIVE SCOPEHAVEN_TARGET_LOCAL_PG_READER
docker stop scopehaven-postgres-local
```

`--rm` removes this container and its anonymous database volume when it stops, including the example table and roles. The commands do not touch an application database.

## What this run shows

This walkthrough was tried with PostgreSQL 17.11 (`postgres:17-alpine`, linux/amd64) and Node.js 24.22.2. The version command above identifies the actual server behind that moving tag. A passing live suite shows the observer's tested behaviour against that server version only. It says nothing about an application, its authorization, or another Postgres version. The synthetic profile entry alone is not an assessment of an application.
