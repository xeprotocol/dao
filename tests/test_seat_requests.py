"""What a signature is bound to, asserted across every route that takes one. No database and no node: the
database handed to a route is one that fails the test if it is touched, so "refused" here always means
"refused before anything was read or written".

Three rules, each with its sites in a table below and each walked over the whole table:

1. A signature is for one deployment. The DAO account and the network are under every signature the
   harness accepts, so a request signed for another deployment is refused by every signed route (XE-2068).
2. A seat's signature is for one action. Every member-action route accepts its own action and refuses each
   of the others, whatever ids the payloads share (XE-2386).
3. A seat route does its work in one order: the address is metered, the signature checked, the seat and its
   right resolved, the seat metered, the payload bound to the path, and only then is the database touched
   (XE-2484).

The tables are checked against the routers: a signed POST route that is in neither fails the first test, so
a new route cannot be added without a row here.
"""

import inspect
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dao import ratelimit
from dao.api import members, public
from dao.auth import signing_target
from dao.canonical import (DOMAIN_INBOX_HTTP, DOMAIN_MEMBER_ACTION, DOMAIN_OPS_APPROVAL, DOMAIN_PROPOSAL,
                           DOMAIN_RESOLUTION, DOMAIN_VOTE)
from dao.config import HumanSeat
from dao.context import get_context
from dao.db import get_db
from dao.ratelimit import INBOX, PROPOSAL, SEAT, VOTE
from xe.keys import KeyPair

MA, RES, OPS = DOMAIN_MEMBER_ACTION, DOMAIN_RESOLUTION, DOMAIN_OPS_APPROVAL
ID, H = "r-0001", "ab" * 32
TO = {"dao": "d" * 64, "network": "xe-test"}

# path: (domain, the action it accepts (member-action routes), the ids its payload names, what the seat needs)
SEAT_ROUTES = {
    "/v1/members/resolutions": (MA, "propose_resolution", {}, "any"),
    "/v1/members/resolutions/{res_id}/sign": (RES, None, {"resolution_id": ID}, "sign_resolutions"),
    "/v1/members/resolutions/{res_id}/withdraw": (MA, "withdraw_resolution", {"resolution_id": ID}, "any"),
    "/v1/members/sessions/registry": (MA, "open_registry_session", {}, "member"),
    "/v1/members/sessions/anchor": (MA, "open_anchor_session", {}, "member"),
    "/v1/members/sessions/{sid}/approve": (OPS, None, {"session_id": ID}, "sign_statechain"),
    "/v1/members/sessions/{sid}/rebuild": (MA, "rebuild_session", {"session_id": ID}, "sign_statechain"),
    "/v1/members/sessions/{sid}/sign": (MA, "sign_session", {"session_id": ID}, "sign_statechain"),
    "/v1/members/sessions/{sid}/cancel": (MA, "cancel_session", {"session_id": ID}, "member"),
    "/v1/members/pause": (MA, "start_pause", {}, "pause"),
    "/v1/members/pause/{pid}/extend": (MA, "extend_pause", {"pause_id": ID}, "pause"),
    "/v1/members/pause/{pid}/lift": (MA, "lift_pause", {"pause_id": ID}, "pause"),
    "/v1/members/pause/{pid}/post": (MA, "post_pause", {"pause_id": ID}, "pause"),
    "/v1/members/inbox/untriaged": (MA, "list_untriaged", {}, "any"),
    "/v1/members/inbox/{mid}/reply": (MA, "reply_message", {"message_id": ID}, "member"),
    "/v1/members/inbox/{mid}/status": (MA, "set_message_status", {"message_id": ID}, "member"),
    "/v1/members/notes": (MA, "post_note", {}, "any"),
    "/v1/proposals/{h}/analysis": (MA, "add_analysis", {"proposal": H}, "any"),
    "/v1/proposals/{h}/decision": (MA, "decide_proposal", {"proposal": H}, "any"),
}
# signed by anyone: no seat, no action, the same deployment binding
OPEN_ROUTES = {
    "/v1/proposals": DOMAIN_PROPOSAL,
    "/v1/proposals/{h}/votes": DOMAIN_VOTE,
    "/v1/votes": DOMAIN_VOTE,
    "/v1/inbox": DOMAIN_INBOX_HTTP,
}
METER = {"/v1/proposals": PROPOSAL, "/v1/proposals/{h}/votes": VOTE, "/v1/votes": VOTE, "/v1/inbox": INBOX}   # seat routes: SEAT
ACTIONS = sorted(a for _, a, _, _ in SEAT_ROUTES.values() if a)


class Untouched:
    """The database a refused request gets: any use of it is the failure."""

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        raise Reached(name)


class Reached(Exception):
    pass


class Claims:
    """A database that answers the signature claim, as used or as new, and nothing after it."""

    def __init__(self, used):
        self.used, self.claims = used, 0

    async def execute(self, _stmt):
        if self.claims and not self.used:
            raise Reached("execute")
        self.claims += 1
        return type("Result", (), {"scalar_one_or_none": lambda _self, used=self.used: None if used else "sig"})()

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        raise Reached(name)


MEMBER = KeyPair.generate()     # a member holding every right
OFFICER = KeyPair.generate()    # a seat, not a member, holding no rights
STRANGER = KeyPair.generate()   # a valid key that holds no seat


class _Config:
    accounts = {"dao": TO["dao"], "fee": "f" * 64}
    human_seats = [
        HumanSeat("m1", "Member One", "member", "founder", MEMBER.pub_key_hex, ("pause", "sign_resolutions", "sign_statechain", "operational_review")),
        HumanSeat("o1", "Officer One", "officer", "clerk", OFFICER.pub_key_hex, ()),
    ]

    def seat_by_key(self, public_key):
        return next((s for s in self.human_seats if s.public_key == public_key.lower()), None)


class _Ctx:
    config = _Config()

    class node:
        network_id = TO["network"]
        chat_pow_difficulty = 0


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(public.router)
    app.include_router(members.router)
    app.dependency_overrides[get_context] = lambda: _Ctx()
    app.dependency_overrides[get_db] = lambda: Untouched()
    ratelimit._buckets._b.clear()
    c = TestClient(app)
    c.database = lambda db: app.dependency_overrides.__setitem__(get_db, lambda: db)
    yield c
    ratelimit._buckets._b.clear()


def _body(kp, domain, payload, to=TO, ts=None):
    ts = ts or time.time_ns()
    return {"payload": payload, "timestamp": ts, "pub_key": kp.pub_key_hex,
            "signature": kp.sign_hex(signing_target(domain, to, payload, ts)), "pow_nonce": 0}


def _url(path):
    return path.format(res_id=ID, sid=ID, pid=ID, mid=ID, h=H)


def _own(path):
    """The payload a route's own request carries past the door (what the service then makes of the rest of
    it is the service's business and other tests')."""
    domain, action, ids, _ = SEAT_ROUTES[path]
    return domain, {**({"action": action} if action else {}), **ids}


def _post(client, path, body):
    """(status, detail) of a refusal. A request that gets as far as the database raises `Reached`."""
    ratelimit._buckets._b.clear()
    r = client.post(_url(path), json=body)
    return r.status_code, r.json().get("detail", "")


def test_every_signed_route_is_in_a_table():
    signed = set()
    for router in (public.router, members.router):
        for route in router.routes:
            if "POST" in route.methods and "req" in inspect.signature(route.endpoint).parameters:
                signed.add(route.path)
    assert signed == set(SEAT_ROUTES) | set(OPEN_ROUTES)
    assert len(ACTIONS) == len(set(ACTIONS)), "two routes must not accept the same action"


@pytest.mark.parametrize("path", [*SEAT_ROUTES, *OPEN_ROUTES])
def test_a_request_signed_for_another_deployment_is_refused_everywhere(client, path):
    domain, payload = _own(path) if path in SEAT_ROUTES else (OPEN_ROUTES[path], {"proposal": H, "message": "hi"})
    for other in ({**TO, "network": "mainnet"}, {**TO, "dao": "e" * 64}, {"dao": "", "network": ""}):
        status, detail = _post(client, path, _body(MEMBER, domain, payload, to=other))
        assert status == 401 and "bad signature" in detail, (path, other)
    # the envelope every earlier signature was made under names no deployment, and is no longer one
    from dao.canonical import digest
    ts = time.time_ns()
    old = {"payload": payload, "timestamp": ts, "pub_key": MEMBER.pub_key_hex, "pow_nonce": 0,
           "signature": MEMBER.sign_hex(digest(domain, {"payload": payload, "timestamp": ts}))}
    assert _post(client, path, old)[0] == 401
    # and signed for this one it passes the door: the first thing it does is touch the database
    with pytest.raises(Reached):
        _post(client, path, _body(MEMBER, domain, payload))


@pytest.mark.parametrize("path", [p for p, (d, *_rest) in SEAT_ROUTES.items() if d == MA])
def test_a_member_action_route_accepts_its_own_action_and_no_other(client, path):
    domain, own = _own(path)
    for action in ACTIONS:
        if action == own["action"]:
            continue
        status, detail = _post(client, path, _body(MEMBER, MA, {**own, "action": action}))
        assert (status, detail) == (400, "signed payload does not name this action"), (path, action)
    # no action at all, and an action that is not a string, are not this action either
    assert _post(client, path, _body(MEMBER, MA, {k: v for k, v in own.items() if k != "action"}))[0] == 400
    assert _post(client, path, _body(MEMBER, MA, {**own, "action": [own["action"]]}))[0] == 400
    with pytest.raises(Reached):
        _post(client, path, _body(MEMBER, MA, own))


@pytest.mark.parametrize("path", [p for p, (d, *_rest) in SEAT_ROUTES.items() if d != MA])
def test_a_route_with_a_domain_of_its_own_takes_no_member_action(client, path):
    domain, own = _own(path)
    for action in ACTIONS:
        assert _post(client, path, _body(MEMBER, MA, {**own, "action": action}))[0] == 401, (path, action)
    with pytest.raises(Reached):
        _post(client, path, _body(MEMBER, domain, own))


@pytest.mark.parametrize("path", [p for p, (_d, _a, ids, _n) in SEAT_ROUTES.items() if ids])
def test_a_seat_request_names_the_record_in_its_path(client, path):
    domain, own = _own(path)
    for field in SEAT_ROUTES[path][2]:
        other = {**own, field: "cd" * 32 if field == "proposal" else "r-0002"}
        status, detail = _post(client, path, _body(MEMBER, domain, other))
        assert status == 400 and "does not name this" in detail, (path, field)
        missing = {k: v for k, v in own.items() if k != field}
        assert _post(client, path, _body(MEMBER, domain, missing))[0] == 400, (path, field)


@pytest.mark.parametrize("path", list(SEAT_ROUTES))
def test_a_key_without_the_seat_is_refused_before_anything_is_written(client, path):
    domain, own = _own(path)
    needs = SEAT_ROUTES[path][3]
    # a perfectly good signature from a key that holds no seat: 403, and no claim, no row, no query
    assert _post(client, path, _body(STRANGER, domain, own)) == (403, "this key does not hold a seat")
    if needs == "any":
        with pytest.raises(Reached):
            _post(client, path, _body(OFFICER, domain, own))
    else:   # a seat that is not a member, or does not hold the right, is refused the same way
        assert _post(client, path, _body(OFFICER, domain, own))[0] == 403


@pytest.mark.parametrize("path", list(SEAT_ROUTES))
def test_a_seat_route_meters_the_address_first_and_the_seat_once_known(client, path):
    domain, own = _own(path)
    # the address's bucket is empty: refused before the signature is looked at (a signature that does not
    # verify would otherwise be a 401)
    bad = {**_body(MEMBER, domain, own), "signature": "00" * 64}
    assert _post(client, path, bad)[0] == 401
    ratelimit._buckets._b.clear()
    ratelimit._buckets._b[f"ip:{SEAT.name}:testclient"] = (0.0, time.monotonic())
    r = client.post(_url(path), json=bad)
    assert r.status_code == 429 and r.headers["retry-after"]
    # the seat's bucket is empty: a good request is refused once it is known to be the seat's own (below),
    # before the route does anything with it
    ratelimit._buckets._b.clear()
    ratelimit._buckets._b[f"acct:{SEAT.name}:{MEMBER.address}"] = (0.0, time.monotonic())
    db = Claims(used=False)
    client.database(db)
    assert client.post(_url(path), json=_body(MEMBER, domain, own)).status_code == 429 and db.claims == 1
    client.database(Untouched())
    # a stranger never reaches the seat's bucket: nobody can spend a seat's allowance but the seat
    ratelimit._buckets._b.clear()
    for _ in range(SEAT.account.burst + 5):
        assert client.post(_url(path), json=_body(STRANGER, domain, own)).status_code == 403
    assert not any(k.startswith("acct:") for k in ratelimit._buckets._b)


@pytest.mark.parametrize("path", [*SEAT_ROUTES, *OPEN_ROUTES])
def test_an_accounts_allowance_is_spent_by_its_own_requests_and_not_by_replays(client, path):
    """XE-7311. A used signature is on the public record with what it signed, so anyone can send the request
    again. On every signed route that is a replay (409) and the signer's bucket is where it was; the
    signer's own new request takes one token."""
    domain, payload = _own(path) if path in SEAT_ROUTES else (OPEN_ROUTES[path], {"proposal": H, "message": "hi"})
    cls = METER.get(path, SEAT)
    key = f"acct:{cls.name}:{MEMBER.address}"
    ratelimit._buckets._b.clear()
    client.database(Claims(used=True))
    for _ in range(cls.account.burst + 3):
        r = client.post(_url(path), json=_body(MEMBER, domain, payload))
        assert r.status_code == 409 and r.json()["detail"] == "this signature has already been used", path
    assert key not in ratelimit._buckets._b, "a replay spends nothing of the signer's"
    ratelimit._buckets._b.clear()
    client.database(Claims(used=False))
    try:   # claimed, charged, and on into the route, which has no database to go on with
        client.post(_url(path), json=_body(MEMBER, domain, payload))
    except Exception:
        pass
    assert ratelimit._buckets._b[key][0] == cls.account.burst - 1
    # no route charges an account any other way
    assert not hasattr(public, "enforce_account") and not hasattr(members, "enforce_account")
    assert not hasattr(public, "claim_signature") and not hasattr(members, "claim_signature")


def test_the_members_console_signs_the_action_its_route_accepts():
    """The page is the other half of the table: every member-action it posts names an action, and the action
    is the one the route it posts to accepts."""
    import re
    from pathlib import Path
    page = (Path(members.__file__).resolve().parents[1] / "templates" / "members.html").read_text(encoding="utf-8")
    lines = [line for line in page.splitlines() if ", MA, " in line]
    assert len(lines) == page.count(", MA, ") == page.count('action: "') >= 15, "every member-action post names its action"
    by_action = {a: re.sub(r"\{\w+\}", "{}", path) for path, (_d, a, _i, _n) in SEAT_ROUTES.items() if a}
    for line in lines:
        action = re.search(r'action: "(\w+)"', line).group(1)
        url = re.search(r"XeSigner\.post\((.*?), MA, ", line).group(1)
        url = re.sub(r"\{\{.*?\}\}", "{}", url)                    # an id the template writes in
        url = re.sub(r'"\s*\+\s*[\w.]+\s*\+\s*"', "{}", url)       # an id the script joins in
        assert url.strip('"') == by_action[action], (action, url)
