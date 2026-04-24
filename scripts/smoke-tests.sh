#!/bin/sh

URL=$1

echo "Running smoke tests on $URL"

curl -f "$URL" || exit 1

echo "Smoke tests passed"
