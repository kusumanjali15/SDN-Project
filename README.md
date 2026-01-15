┌─────────────┐
│   Ryu       │
│ Controller  │ ← Controls all switches via OpenFlow
└──────┬──────┘
       │ (OpenFlow protocol on port 6653)
       │
       ├─────────┬─────────┬─────────┬─────────┐
       ↓         ↓         ↓         ↓         ↓
      S1        S2        S3        S4        S5
       │
       │ (Port mirroring - copies of packets)
       ↓
   Suricata (receives mirrored traffic)


   # Next: I want suricata to send alerts to Ryu
   # Ryu should block the IPs.
