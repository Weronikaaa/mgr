#!/bin/bash

URL=$1
MAX_RETRIES=10
SLEEP=5

echo "Running smoke tests on $URL"

for i in $(seq 1 $MAX_RETRIES); do
  echo "Attempt $i..."

  STATUS=$(curl -s -o /dev/null -w "%{http_code}" $URL)

  echo "Status: $STATUS"

  if [ "$STATUS" = "200" ]; then
    echo "✅ PASS"
    exit 0
  fi

  sleep $SLEEP
done

echo "❌ FAIL after $MAX_RETRIES attempts"
exit 1
