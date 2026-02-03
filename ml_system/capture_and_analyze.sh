#!/bin/bash
# Capture packets and feed to ML analyzer

sudo tcpdump -i s2-eth1 -n -l 2>/dev/null | while read line; do
    echo "$line"
    # Parse and send to ML (simplified)
done
