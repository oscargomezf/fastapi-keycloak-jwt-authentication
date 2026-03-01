#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# /**
#  * @file restore.sh
#  * @author Oscar Gomez Fuente <oscargomezf@gmail.com>
#  * @modified Oscar Gomez Fuente <oscargomezf@gmail.com>
#  * @date 2026-03-01 12:25:00 
#  * @version v1.0
#  * @section DESCRIPTION
#  *     Script for restoring a Keycloak database from a backup dump
#  *     into PostgreSQL.
#  */
# -----------------------------------------------------------------------------

set -euo pipefail

echo "[INFO] Restoring Keycloak database into PostgreSQL..."
echo "[INFO] DB: $POSTGRES_DB | USER: $POSTGRES_USER"

# Wait for the internal Postgres during init phase to accept connections.
# Sometimes init scripts can race; this makes the restore robust.
for i in {1..30}; do
	if pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" > /dev/null 2>&1; then
		break
	fi
	echo "[INFO] Waiting for PostgreSQL to be ready... (attempt $i/30)"
sleep 1
done

# Ensure target database exists. On fresh init it will,
# but this makes the script idempotent if the image behavior changes.
#createdb -U "$POSTGRES_USER" "$POSTGRES_DB" 2>/dev/null || true

# Perform restore from a custom-format dump (-Fc).
# --clean: drop objects before recreating (safe on empty DB; helpful for repeatability)
# --no-owner: avoid ownership issues if dump was created by a different role
pg_restore \
	--verbose \
	--clean \
	--if-exists \
	--no-owner \
	--no-privileges \
	-1 \
	--no-owner \
	-U "$POSTGRES_USER" \
	-d "$POSTGRES_DB" \
	/docker-entrypoint-initdb.d/keycloak_backup.dump

echo "[INFO] Restore completed"
