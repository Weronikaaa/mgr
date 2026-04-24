#!/bin/sh

URL=$1

if [ -z "$URL" ]; then
  echo "❌ No URL provided"
  exit 1
fi

echo "Running smoke tests on $URL"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$URL/")

echo "Status: $STATUS"

if [ "$STATUS" -ne 200 ]; then
  echo "❌ FAIL"
  exit 1
fi

echo "✅ OK"
