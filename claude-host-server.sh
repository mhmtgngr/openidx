#!/bin/bash
# claude-host-server.sh - Simple HTTP server to run Claude on host
# Run this on the HOST machine (not in container)

PORT="${CLAUDE_SERVER_PORT:-8765"

echo "Starting Claude Host Server on port $PORT..."

while true; do
  REQUEST=$(echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" | nc -l $PORT | grep -P "^POST|^\{")

  if [ -n "$REQUEST" ]; then
    # Extract JSON from request
    JSON=$(echo "$REQUEST" | grep -oP '^\{.*\}$')

    if [ -n "$JSON" ]; then
      # Parse instruction
      INSTRUCTION=$(echo "$JSON" | grep -oP '"instruction":\s*"[^"]*"' | sed 's/"instruction":\s*"\([^"]*\)"/\1/')

      if [ -n "$INSTRUCTION" ]; then
        echo "[$(date)] Running: $INSTRUCTION" >> /home/cmit/openidx/claude-host-server.log

        # Run claude
        cd /home/cmit/openidx
        OUTPUT=$(echo "$INSTRUCTION" | claude -p 2>&1)
        RESULT=$?

        echo "[$(date)] Exit code: $RESULT" >> /home/cmit/openidx/claude-host-server.log

        # Return JSON response
        if [ $RESULT -eq 0 ]; then
          echo "{\"status\":\"success\",\"output\":\"$OUTPUT\"}" | nc -l $PORT &
        else
          echo "{\"status\":\"error\",\"message\":\"Exit code $RESULT\"}" | nc -l $PORT &
        fi
      fi
    fi
  fi
done
