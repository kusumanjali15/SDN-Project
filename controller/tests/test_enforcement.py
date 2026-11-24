"""Unit tests for the enforcement policy logic (no Ryu or Mininet needed)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from controller.enforcement import (  # noqa: E402
    PersistenceTracker, BlockRecord, block_timeout, load_sid_allowlist, make_cookie,
    cookie_for_ip, is_policy_cookie, ip_from_cookie, proto_number, COOKIE_MASK_TAG_AND_IP,
)
from controller.event_log import EventLogger  # noqa: E402


def test_cookie_roundtrip_and_mask():
    c1, c2 = make_cookie("10.0.1.1"), make_cookie("10.0.1.1")
    assert c1 != c2                                   # each decision is distinct
    assert is_policy_cookie(c1) and ip_from_cookie(c1) == "10.0.1.1"
    # one masked delete matches every decision for the IP, and no other IP
    assert c1 & COOKIE_MASK_TAG_AND_IP == cookie_for_ip("10.0.1.1")
    assert make_cookie("10.0.1.3") & COOKIE_MASK_TAG_AND_IP != cookie_for_ip("10.0.1.1")
    assert not is_policy_cookie(0)


def test_persistence_window():
    t = PersistenceTracker(r=3, window=10)
    assert not t.record("a", now=0) and not t.record("a", now=1)
    assert t.record("a", now=2)                       # 3 within 10 s
    t2 = PersistenceTracker(r=3, window=10)
    assert not t2.record("b", now=0) and not t2.record("b", now=11)
    assert not t2.record("b", now=22)                 # spread out: never persistent


def test_block_timeout_growth_and_cap():
    assert [block_timeout(120, 2, 900, n) for n in (1, 2, 3, 4)] == [120, 240, 480, 900]
    assert block_timeout(0, 2, 900, 5) == 0           # 0 = permanent


def test_scoped_and_blanket_matching():
    s = BlockRecord("10.0.1.1", 1, "scoped", "10.0.1.3", 1, "r", "signature", 0, None)
    assert s.matches("10.0.1.1", "10.0.1.3", 1)
    assert not s.matches("10.0.1.1", "10.0.1.3", 6)
    assert not s.matches("10.0.1.3", "10.0.1.1", 1)
    b = BlockRecord("10.0.1.1", 1, "blanket", None, None, "r", "manual", 0, None)
    assert b.matches("10.0.1.1", "x", 6) and b.matches("x", "10.0.1.1", 17)


def test_proto_numbers():
    assert proto_number("ICMP") == 1 and proto_number("tcp") == 6 and proto_number(17) == 17
    assert proto_number(None) is None and proto_number("bogus") is None


def test_sid_allowlist_file():
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sids = load_sid_allowlist(os.path.join(here, "config", "auto_block_sids.txt"))
    assert 1000001 in sids and 2000003 not in sids   # policy violations excluded
    assert load_sid_allowlist("/nonexistent") is None


def test_event_logger_tags_current_run():
    d = tempfile.mkdtemp()
    run_file, ev_file = os.path.join(d, "run.json"), os.path.join(d, "events.jsonl")
    json.dump({"run_id": "r1", "policy": "signature", "attack": "icmp_flood"}, open(run_file, "w"))
    log = EventLogger(ev_file, run_file)
    log.log("decision", src_ip="10.0.1.1", skip=None)
    e = json.loads(open(ev_file).read().strip())
    assert e["run_id"] == "r1" and e["policy"] == "signature" and e["stage"] == "decision"
    assert "skip" not in e and e["src_ip"] == "10.0.1.1"
