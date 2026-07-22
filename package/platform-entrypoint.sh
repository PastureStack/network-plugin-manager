#!/bin/bash
set -e

/usr/bin/update-platform-ca

exec "$@"
