#!/bin/sh
set -eu

# Ensure mounted data/storage paths are writable by the runtime user.
mkdir -p /app/data /app/storage

if [ "$(id -u)" = "0" ]; then
  chown secushare:secushare /app /app/data /app/storage
  exec su-exec secushare "$@"
fi

exec "$@"
