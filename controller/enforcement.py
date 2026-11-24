"""
Enforcement policy logic for the SDN-IDS controller (no Ryu imports, so it
can be unit-tested on any machine).

Implements what Section IV of the paper describes:
  - persistence: act on ML evidence only after r positives within T seconds
  - finite-lifetime rules: hard timeout per block, longer for repeat offenders
  - scoped enforcement: drop (src, dst, protocol) instead of the whole host
  - approved signatures: only allow-listed Suricata SIDs trigger automatic action
  - policy cookies: every rule carries a cookie encoding the blocked IP, so all
    rules for one IP can be updated or removed with one cookie-masked request
"""
import ipaddress
import itertools
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Set

# --- Policy cookies ---------------------------------------------------------
# 64-bit OpenFlow cookie layout:
#   bits 63..48  tag 0xB10C   (marks rules installed by this policy)
#   bits 47..32  decision sequence number (wraps at 65535)
#   bits 31..0   blocked source IPv4 address
COOKIE_TAG = 0xB10C
COOKIE_TAG_MASK = 0xFFFF << 48
COOKIE_IP_MASK = 0xFFFFFFFF
COOKIE_MASK_TAG_AND_IP = COOKIE_TAG_MASK | COOKIE_IP_MASK

_seq = itertools.count(1)


def make_cookie(ip: str, seq: Optional[int] = None) -> int:
    """Cookie for a new decision on `ip`."""
    if seq is None:
        seq = next(_seq)
    return (COOKIE_TAG << 48) | ((seq & 0xFFFF) << 32) | int(ipaddress.IPv4Address(ip))


def cookie_for_ip(ip: str) -> int:
    """Cookie value to use with COOKIE_MASK_TAG_AND_IP to match every rule for `ip`."""
    return (COOKIE_TAG << 48) | int(ipaddress.IPv4Address(ip))


def is_policy_cookie(cookie: int) -> bool:
    return (cookie >> 48) & 0xFFFF == COOKIE_TAG


def ip_from_cookie(cookie: int) -> str:
    return str(ipaddress.IPv4Address(cookie & COOKIE_IP_MASK))


# --- Protocols ---------------------------------------------------------------
PROTO_NUMBERS = {"ICMP": 1, "TCP": 6, "UDP": 17, "IPV6-ICMP": 58}


def proto_number(proto) -> Optional[int]:
    """Accept 'TCP', 'tcp', 6, '6' -> 6. Unknown -> None."""
    if proto is None:
        return None
    if isinstance(proto, int):
        return proto
    p = str(proto).strip().upper()
    if p.isdigit():
        return int(p)
    return PROTO_NUMBERS.get(p)


# --- Persistence ---------------------------------------------------------------
class PersistenceTracker:
    """Counts positive detections per key in a sliding window of `window` seconds.

    `record(key)` returns True once the key has at least `r` positives inside
    the window, i.e. the evidence has persisted long enough to act on.
    """

    def __init__(self, r: int = 3, window: float = 10.0):
        self.r = max(1, int(r))
        self.window = float(window)
        self._hits: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def record(self, key: str, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            q = self._hits[key]
            q.append(now)
            while q and now - q[0] > self.window:
                q.popleft()
            return len(q) >= self.r

    def count(self, key: str, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            q = self._hits.get(key, deque())
            return sum(1 for t in q if now - t <= self.window)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


# --- Blocks --------------------------------------------------------------------
@dataclass
class BlockRecord:
    """One active block decision."""
    ip: str
    cookie: int
    scope: str                      # "scoped" or "blanket"
    dst_ip: Optional[str]
    ip_proto: Optional[int]
    reason: str
    source: str                     # "signature", "ml", "manual", "restored"
    created: float
    expires_at: Optional[float]     # None = never expires
    offence: int = 1
    acked_dpids: Set[int] = field(default_factory=set)
    sent_dpids: Set[int] = field(default_factory=set)

    def matches(self, src_ip: str, dst_ip: str, ip_proto: Optional[int]) -> bool:
        """Would this block drop a packet with these fields?"""
        if self.scope == "blanket":
            return src_ip == self.ip or dst_ip == self.ip
        if src_ip != self.ip:
            return False
        if self.dst_ip and dst_ip != self.dst_ip:
            return False
        if self.ip_proto is not None and ip_proto != self.ip_proto:
            return False
        return True

    def remaining(self, now: Optional[float] = None) -> Optional[int]:
        """Seconds left (for re-installing on a reconnecting switch). None = permanent."""
        if self.expires_at is None:
            return None
        now = time.time() if now is None else now
        return max(1, int(round(self.expires_at - now)))


def block_timeout(base: int, multiplier: float, max_timeout: int, offence: int) -> int:
    """Hard timeout for the n-th offence: base * multiplier^(n-1), capped. 0 = permanent."""
    if base <= 0:
        return 0
    t = base * (multiplier ** max(0, offence - 1))
    return int(min(t, max_timeout)) if max_timeout > 0 else int(t)


# --- Approved signatures -----------------------------------------------------
def load_sid_allowlist(path) -> Optional[Set[int]]:
    """Read approved SIDs (one per line, '#' comments). Missing file -> None (no allowlist)."""
    p = Path(path)
    if not p.is_file():
        return None
    sids = set()
    for line in p.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line.isdigit():
            sids.add(int(line))
    return sids
