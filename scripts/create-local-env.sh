#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
umask 077
if [ -e .env ]; then
    printf '%s\n' '.env already exists. Keep the existing encryption key to read stored secrets.' >&2
    exit 1
fi
set -C
{
    printf 'DB_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'DEMO_INFO_PASSWORD=%s\n' "$(openssl rand -hex 16)"
    printf 'DEMO_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 16)"
    printf 'DEMO_MEMBER_PASSWORD=%s\n' "$(openssl rand -hex 16)"
    printf 'SECRET_ENCRYPTION_KEY=%s\n' "$(openssl rand -base64 32)"
} > .env
printf '%s\n' 'Created .env with local credentials. Docker Compose reads it automatically.'
