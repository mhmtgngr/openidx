#!/bin/bash
read INPUT
ACTION=$(echo "$INPUT" | grep -o '"action":"[^"]*"' | cut -d'"' -f4)
case "$ACTION" in
  check)
    echo '{"status":"pass","score":1.0,"message":"Hello from plugin!","details":{"plugin":"hello-check"}}'
    ;;
  info)
    echo '{"name":"hello-check","version":"1.0.0","check_types":["hello"]}'
    ;;
  *)
    echo '{"status":"error","score":0,"message":"unknown action"}'
    ;;
esac
