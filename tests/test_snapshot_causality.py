"""Snapshot causality tests: multi-hop relay taint conservation and lease settle expiry/renewal checks."""

from __future__ import annotations

import httpx
import pytest

from dao.chainops import CAUSAL_CHECK_NS, MAX_CAUSAL_LOOKUPS, SNAPSHOT_RULE, account_snapshot
from xe.client import XeClient, XeError

H = 3600 * 1_000_000_000


class _Lattice:
    def __init__(self, chains: dict[str, list[dict]], blocks: dict[str, dict] | None = None):
        self.chains = chains
        self.blocks = dict(blocks or {})
        for acct, ch in chains.items():
            for b in ch:
                b.setdefault("account", acct)
                if b.get("hash"):
                    self.blocks.setdefault(b["hash"], b)
        self.block_lookups = 0
        self.chain_lookups = 0

    async def full_chain(self, account: str) -> list[dict]:
        self.chain_lookups += 1
        if account not in self.chains:
            raise XeError(404, "no such account")
        return self.chains[account]

    async def block(self, h: str) -> dict:
        self.block_lookups += 1
        if h not in self.blocks:
            raise XeError(404, "no such block")
        return self.blocks[h]


async def test_a_relay_in_the_causal_window_cannot_launder_a_send_dated_after_the_snapshot():
    """A post-snapshot send routed through intermediate relay accounts dated at or before the snapshot
    carries its taint through every hop, and a relay that holds both clean and tainted XE spends its taint
    first so total clean weight is conserved."""
    at = 100 * H
    amt = 1_000_000_000
    chains: dict[str, list[dict]] = {}
    blocks: dict[str, dict] = {"faucet": {"type": "send", "timestamp": at - 10 * H, "hash": "faucet"}}

    w0_recv = {"type": "receive", "asset": "XE", "balance": amt, "timestamp": at - 9 * H,
               "hash": "w0_r", "source": "faucet", "previous": "0"}
    w0_send = {"type": "send", "asset": "XE", "balance": 0, "amount": amt, "timestamp": at + 100,
               "hash": "w0_s", "destination": "R_1", "previous": "w0_r"}
    chains["W_0"] = [w0_recv, w0_send]

    prev_send = "w0_s"
    for i in range(1, 21):
        r_acct, w_acct = f"R_{i}", f"W_{i}"
        r_recv = {"type": "receive", "asset": "XE", "balance": amt, "timestamp": at - 500 + i * 2,
                  "hash": f"r{i}_r", "source": prev_send, "previous": "0"}
        r_send = {"type": "send", "asset": "XE", "balance": 0, "amount": amt,
                  "timestamp": at - 500 + i * 2 + 1, "hash": f"r{i}_s", "destination": w_acct,
                  "previous": f"r{i}_r"}
        chains[r_acct] = [r_recv, r_send]

        w_recv = {"type": "receive", "asset": "XE", "balance": amt, "timestamp": at - 400 + i * 2,
                  "hash": f"w{i}_r", "source": f"r{i}_s", "previous": "0"}
        w_send = {"type": "send", "asset": "XE", "balance": 0, "amount": amt, "timestamp": at + 100 + i,
                  "hash": f"w{i}_s", "destination": f"R_{i + 1}", "previous": f"w{i}_r"}
        chains[w_acct] = [w_recv, w_send]
        prev_send = f"w{i}_s"

    lat = _Lattice(chains, blocks)
    snaps = [await account_snapshot(lat, f"W_{i}", at) for i in range(21)]
    assert snaps[0]["exists"] is True and snaps[0]["balance"] == amt and snaps[0]["rule"] == SNAPSHOT_RULE
    for i in range(1, 21):
        assert snaps[i]["exists"] is False and snaps[i]["balance"] == 0
        assert snaps[i]["excluded_receives"] == [f"w{i}_r"]
    assert sum(s["balance"] for s in snaps) == amt

    # A relay with 400 clean XE and 600 tainted XE sends 700 XE to B1, then 300 XE to B2:
    # the first send spends all 600 taint and 100 clean (so B1 gets 100 clean), and B2 gets 300 clean.
    mix_chains = {
        "A": [
            {"type": "receive", "asset": "XE", "balance": 600, "timestamp": at - 9 * H,
             "hash": "a_r", "source": "faucet", "previous": "0"},
            {"type": "send", "asset": "XE", "balance": 0, "amount": 600, "timestamp": at + 50,
             "hash": "a_s", "destination": "M", "previous": "a_r"},
        ],
        "M": [
            {"type": "receive", "asset": "XE", "balance": 400, "timestamp": at - 8 * H,
             "hash": "m_r0", "source": "faucet", "previous": "0"},
            {"type": "receive", "asset": "XE", "balance": 1000, "timestamp": at - 60,
             "hash": "m_r1", "source": "a_s", "previous": "m_r0"},
            {"type": "send", "asset": "XE", "balance": 300, "amount": 700, "timestamp": at - 50,
             "hash": "m_s1", "destination": "B1", "previous": "m_r1"},
            {"type": "send", "asset": "XE", "balance": 0, "amount": 300, "timestamp": at - 40,
             "hash": "m_s2", "destination": "B2", "previous": "m_s1"},
        ],
        "B1": [
            {"type": "receive", "asset": "XE", "balance": 700, "timestamp": at - 30,
             "hash": "b1_r", "source": "m_s1", "previous": "0"},
        ],
        "B2": [
            {"type": "receive", "asset": "XE", "balance": 300, "timestamp": at - 20,
             "hash": "b2_r", "source": "m_s2", "previous": "0"},
        ],
    }
    mix_lat = _Lattice(mix_chains, blocks)
    a_snap = await account_snapshot(mix_lat, "A", at)
    m_snap = await account_snapshot(mix_lat, "M", at)
    b1_snap = await account_snapshot(mix_lat, "B1", at)
    b2_snap = await account_snapshot(mix_lat, "B2", at)
    assert a_snap["balance"] == 600 and m_snap["balance"] == 0
    assert b1_snap["balance"] == 100 and b1_snap["excluded_receives"] == ["b1_r"] and b1_snap["exists"]
    assert b2_snap["balance"] == 300 and b2_snap["excluded_receives"] == [] and b2_snap["exists"]
    assert a_snap["balance"] + m_snap["balance"] + b1_snap["balance"] + b2_snap["balance"] == 1000


async def test_a_relay_chain_past_the_lookup_bound_is_excluded_rather_than_counted():
    """A chain of windowed relays deeper than MAX_CAUSAL_LOOKUPS hits the cap and excludes the unverified
    receive rather than trusting an unreached ancestor."""
    at = 100 * H
    depth = MAX_CAUSAL_LOOKUPS + 6
    chains: dict[str, list[dict]] = {
        "Origin": [
            {"type": "receive", "asset": "XE", "balance": 500, "timestamp": at - 5 * H,
             "hash": "o_r", "source": "root", "previous": "0"},
            {"type": "send", "asset": "XE", "balance": 0, "amount": 500, "timestamp": at - H,
             "hash": "h_0", "destination": "H_1", "previous": "o_r"},
        ]
    }
    for i in range(1, depth + 1):
        chains[f"H_{i}"] = [
            {"type": "receive", "asset": "XE", "balance": 500, "timestamp": at - H + i * 2,
             "hash": f"r_{i}", "source": f"h_{i - 1}", "previous": "0"},
            {"type": "send", "asset": "XE", "balance": 0, "amount": 500, "timestamp": at - H + i * 2 + 1,
             "hash": f"h_{i}", "destination": f"H_{i + 1}", "previous": f"r_{i}"},
        ]
    chains["Leaf"] = [
        {"type": "receive", "asset": "XE", "balance": 500, "timestamp": at - 10,
         "hash": "leaf_r", "source": f"h_{depth}", "previous": "0"}
    ]
    lat = _Lattice(chains, {"root": {"type": "send", "timestamp": at - 6 * H, "hash": "root"}})
    snap = await account_snapshot(lat, "Leaf", at)
    assert snap["lookups_capped"] is True
    assert snap["balance"] == 0 and snap["exists"] is False and snap["excluded_receives"] == ["leaf_r"]
    assert lat.block_lookups <= MAX_CAUSAL_LOOKUPS and lat.chain_lookups <= MAX_CAUSAL_LOOKUPS + 1


async def test_a_lease_settle_counts_only_when_the_lease_and_all_renewals_expired_by_the_snapshot():
    """A lease_settle dated at or before the snapshot is excluded when its attestations, its base duration,
    its provider accept, or any consumer renewal puts the lease's completion after the snapshot."""
    at = 100 * H
    # 1. Attested settlement median after at_ns is excluded without even needing a source lookup.
    s_late_att = {
        "type": "lease_settle", "asset": "XE", "balance": 5_000, "timestamp": at - 10, "hash": "s_att",
        "source": "L1", "attestations": [{"public_key": "k1", "timestamp": at + 1, "signature": "sig"}],
    }
    lat1 = _Lattice({"P": [s_late_att]}, {"L1": {"type": "lease", "timestamp": at - 2 * H, "hash": "L1"}})
    p1 = await account_snapshot(lat1, "P", at)
    assert p1["balance"] == 0 and p1["excluded_receives"] == ["s_att"] and lat1.block_lookups == 0

    # 2. Lease opened before at_ns whose base duration expires after at_ns is excluded.
    lease_unexpired = {"type": "lease", "account": "C", "asset": "XUSD", "timestamp": at - 30 * 10**9,
                       "duration": 60, "hash": "L2"}
    s_unexpired = {"type": "lease_settle", "asset": "XE", "balance": 5_000, "timestamp": at - 1,
                   "hash": "s_unexp", "source": "L2"}
    lat2 = _Lattice({"P": [s_unexpired], "C": [lease_unexpired]})
    p2 = await account_snapshot(lat2, "P", at)
    assert p2["balance"] == 0 and p2["excluded_receives"] == ["s_unexp"]

    # 3. Lease whose base duration expired before at_ns, but renewed by consumer after at_ns, is excluded.
    lease_open = {"type": "lease", "account": "C", "asset": "XUSD", "timestamp": at - 120 * 10**9,
                  "duration": 60, "hash": "L3"}
    lease_renew = {"type": "lease_renew", "account": "C", "asset": "XUSD", "timestamp": at + 5 * 10**9,
                   "duration": 60, "source": "L3", "hash": "LR3"}
    s_renewed = {"type": "lease_settle", "asset": "XE", "balance": 50_000, "timestamp": at - 1,
                 "hash": "s_ren", "source": "L3"}
    lat3 = _Lattice({"P": [s_renewed], "C": [lease_open, lease_renew]})
    p3 = await account_snapshot(lat3, "P", at)
    assert p3["balance"] == 0 and p3["excluded_receives"] == ["s_ren"]

    # 4. Once the renewal and cumulative expiry are both at or before at_ns, the settle counts.
    lease_renew["timestamp"] = at - 60 * 10**9
    lease_open["timestamp"] = at - 180 * 10**9
    lat4 = _Lattice({"P": [s_renewed], "C": [lease_open, lease_renew]})
    p4 = await account_snapshot(lat4, "P", at)
    assert p4["balance"] == 50_000 and p4["excluded_receives"] == [] and p4["exists"] is True

    # 5. Client typing refuses non-integer duration, start_time, or attestation timestamps.
    body = {"v": {}}
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=body["v"]))
    client = XeClient("http://node", transport=transport)
    body["v"] = {"hash": "h", "type": "lease_settle", "duration": "60",
                 "attestations": [{"timestamp": "123", "public_key": "k", "signature": "s"}]}
    blk = await client.block("h")
    assert blk["duration"] == 60 and blk["attestations"][0]["timestamp"] == 123
    for bad in ({"hash": "h", "duration": "bad"}, {"hash": "h", "attestations": "bad"},
                {"hash": "h", "attestations": [{"timestamp": "bad"}]}):
        body["v"] = bad
        with pytest.raises(XeError):
            await client.block("h")
    await client.aclose()
    assert CAUSAL_CHECK_NS > 0


async def test_diamond_dag_and_relayed_unexpired_lease_remain_tainted():
    """Diamond fan-out/fan-in relays and relays forwarding unexpired lease settlements conserve taint."""
    at = 100 * H
    # Diamond: tainted send after snapshot splits into R1 and R2, then merges into Target
    diamond_chains = {
        "Src": [
            {"type": "receive", "asset": "XE", "balance": 1000, "timestamp": at - 5 * H,
             "hash": "src_r", "source": "faucet", "previous": "0"},
            {"type": "send", "asset": "XE", "balance": 500, "amount": 500, "timestamp": at + 10,
             "hash": "s_r1", "destination": "R1", "previous": "src_r"},
            {"type": "send", "asset": "XE", "balance": 0, "amount": 500, "timestamp": at + 20,
             "hash": "s_r2", "destination": "R2", "previous": "s_r1"},
        ],
        "R1": [
            {"type": "receive", "asset": "XE", "balance": 500, "timestamp": at - 50,
             "hash": "r1_r", "source": "s_r1", "previous": "0"},
            {"type": "send", "asset": "XE", "balance": 0, "amount": 500, "timestamp": at - 40,
             "hash": "r1_s", "destination": "Target", "previous": "r1_r"},
        ],
        "R2": [
            {"type": "receive", "asset": "XE", "balance": 500, "timestamp": at - 30,
             "hash": "r2_r", "source": "s_r2", "previous": "0"},
            {"type": "send", "asset": "XE", "balance": 0, "amount": 500, "timestamp": at - 20,
             "hash": "r2_s", "destination": "Target", "previous": "r2_r"},
        ],
        "Target": [
            {"type": "receive", "asset": "XE", "balance": 500, "timestamp": at - 15,
             "hash": "t_r1", "source": "r1_s", "previous": "0"},
            {"type": "receive", "asset": "XE", "balance": 1000, "timestamp": at - 10,
             "hash": "t_r2", "source": "r2_s", "previous": "t_r1"},
        ],
    }
    lat = _Lattice(diamond_chains, {"faucet": {"type": "send", "timestamp": at - 10 * H, "hash": "faucet"}})
    snap = await account_snapshot(lat, "Target", at)
    assert snap["balance"] == 0 and snap["exists"] is False
    assert snap["excluded_receives"] == ["t_r1", "t_r2"]

    # Relayed unexpired lease settle: Provider settles an unexpired lease and sends to Relay, then to Voter
    lease_unexpired = {"type": "lease", "account": "Client", "asset": "XUSD",
                       "timestamp": at - 30 * 10**9, "duration": 60, "hash": "L_unexp"}
    provider_chains = {
        "Client": [lease_unexpired],
        "Provider": [
            {"type": "lease_settle", "asset": "XE", "balance": 800, "timestamp": at - 50,
             "hash": "p_settle", "source": "L_unexp", "previous": "0"},
            {"type": "send", "asset": "XE", "balance": 0, "amount": 800, "timestamp": at - 40,
             "hash": "p_send", "destination": "Relay", "previous": "p_settle"},
        ],
        "Relay": [
            {"type": "receive", "asset": "XE", "balance": 800, "timestamp": at - 30,
             "hash": "relay_r", "source": "p_send", "previous": "0"},
            {"type": "send", "asset": "XE", "balance": 0, "amount": 800, "timestamp": at - 20,
             "hash": "relay_s", "destination": "Voter", "previous": "relay_r"},
        ],
        "Voter": [
            {"type": "receive", "asset": "XE", "balance": 800, "timestamp": at - 10,
             "hash": "voter_r", "source": "relay_s", "previous": "0"},
        ],
    }
    lat_lease = _Lattice(provider_chains)
    voter_snap = await account_snapshot(lat_lease, "Voter", at)
    assert voter_snap["balance"] == 0 and voter_snap["exists"] is False
    assert voter_snap["excluded_receives"] == ["voter_r"]

