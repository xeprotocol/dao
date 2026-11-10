"""Config as data: Schedule B, Schedule C, registry, charter, copy registers.

Loaded once at startup, hashed, and exposed read-only. A change to any file is a resolution matter;
the worker records the hash of each file in the log at boot so config history is itself a record.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from xe.keys import derive_address


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def slugify(text: str) -> str:
    """'Legal & Compliance' -> 'legal-and-compliance'; used for seat page URLs."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower().replace("&", " and ")).strip("-")


@dataclass(frozen=True)
class HumanSeat:
    id: str
    name: str
    kind: str          # member | officer
    role: str
    public_key: str
    may: tuple[str, ...]

    @property
    def slug(self) -> str:
        return self.id  # roles repeat between people (two founders); the id is the stable handle

    @property
    def account(self) -> str:
        return derive_address(self.public_key) if self.public_key else ""

    @property
    def is_member(self) -> bool:
        return self.kind == "member"

    def can(self, right: str) -> bool:
        return right in self.may


@dataclass(frozen=True)
class AgentSeat:
    id: str
    role: str
    cls: str
    status: str
    model: str
    account: str
    tool_scopes: tuple[str, ...]
    optional: bool = False
    summary: str = ""

    @property
    def slug(self) -> str:
        return slugify(self.role)


@dataclass
class Config:
    dir: Path
    schedule_b: dict
    schedule_c: dict
    registry: dict
    charter_md: str
    copy_public: dict
    copy_legal: dict
    kill_list: dict
    hashes: dict[str, str]
    prompts: dict[str, str]   # seat id (or "_preamble") -> markdown; config only, nothing calls a model in v1
    signer_accounts: dict[str, str] = field(default_factory=dict)   # name -> address, from the loaded keyfile

    # ---- seats ----------------------------------------------------------------------------

    @property
    def human_seats(self) -> list[HumanSeat]:
        out = []
        for s in self.schedule_c.get("human_seats", []):
            out.append(HumanSeat(
                id=s["id"], name=s.get("name", ""), kind=s.get("kind", "officer"), role=s.get("role", ""),
                public_key=(s.get("public_key") or "").lower(), may=tuple(s.get("may", [])),
            ))
        return out

    @property
    def members(self) -> list[HumanSeat]:
        return [s for s in self.human_seats if s.is_member]

    @property
    def agent_seats(self) -> list[AgentSeat]:
        out = []
        for s in self.schedule_c.get("agent_seats", []):
            out.append(AgentSeat(
                id=s["id"], role=s.get("role", ""), cls=s.get("class", "specialist"), status=s.get("status", "designed"),
                model=s.get("model", "") or "", account=(s.get("account") or "").lower(),
                tool_scopes=tuple(s.get("tool_scopes", [])), optional=bool(s.get("optional", False)),
                summary=" ".join((s.get("summary") or "").split()),
            ))
        return out

    def seat_page(self, slug: str) -> tuple[str, HumanSeat | AgentSeat] | None:
        """Resolve a /seats/{slug} path: agent role slug or seat id, or a human seat id."""
        slug = slug.lower()
        for a in self.agent_seats:
            if slug in (a.slug, a.id):
                return "agent", a
        for h in self.human_seats:
            if slug == h.id:
                return "human", h
        return None

    @property
    def tool_scope_glossary(self) -> dict[str, str]:
        return {k: str(v) for k, v in (self.schedule_c.get("tool_scopes") or {}).items()}

    def seat_by_key(self, public_key: str) -> HumanSeat | None:
        pk = public_key.lower()
        for s in self.human_seats:
            if s.public_key and s.public_key == pk:
                return s
        return None

    def seat(self, seat_id: str) -> HumanSeat | None:
        for s in self.human_seats:
            if s.id == seat_id:
                return s
        return None

    @property
    def agent_accounts(self) -> set[str]:
        return {s.account for s in self.agent_seats if s.account}

    @property
    def accounts(self) -> dict[str, str]:
        """The company's accounts by name. Schedule C may name them; the signer is authoritative for the
        ones it holds keys for (`dao`, `fee`), so a deployment that left the file blank still knows them
        and every reader of this property (fee checks, inbox, registers, the vote exclusion) agrees (XE-1479)."""
        out = {k: (v or "").lower() for k, v in (self.schedule_c.get("accounts") or {}).items()}
        out.update({k: v.lower() for k, v in self.signer_accounts.items() if v})
        return out

    @property
    def mode(self) -> str:
        return self.schedule_c.get("mode", "members-direct")

    # ---- schedule B accessors --------------------------------------------------------------

    @property
    def open_vote(self) -> dict:
        return self.schedule_b.get("open_vote", {})

    @property
    def windows(self) -> dict:
        return self.schedule_b.get("windows", {})

    @property
    def pause(self) -> dict:
        return self.schedule_b.get("pause", {})

    @property
    def cadence(self) -> dict:
        return self.schedule_b.get("cadence", {})

    def excluded_accounts(self) -> set[str]:
        """Accounts whose vote weighs nothing: the company's own (treasury, fee, dao) and any Schedule B
        names. Agent seats are not here: their weight is bounded by `agents.max_weight_share` in the tally
        and their participation by `exclude_agent_accounts`; zeroing them would make both dead (XE-1479)."""
        ex = {a.lower() for a in self.open_vote.get("excluded_accounts", []) if a}
        for name in ("treasury", "fee", "dao"):
            a = self.accounts.get(name)
            if a:
                ex.add(a)
        return ex

    def pinned_rules(self) -> dict:
        """The rules snapshot pinned to a proposal when it opens."""
        ov = self.open_vote
        return {
            "window_days": self.windows.get("open_vote_days", 21),
            "quorum_wallets": ov.get("quorum_wallets", 20),
            "participating_wallet": ov.get("participating_wallet", {}),
            "pass_mark_fraction": ov.get("pass_mark_fraction", 0.5),
            "weight_asset": ov.get("weight_asset", "XE"),
            "fee_micro_xe": ov.get("fee_micro_xe", 0),
            "fee_on_quorum": ov.get("fee_on_quorum", "refund"),
            "fee_below_quorum": ov.get("fee_below_quorum", "burn"),
            "agents": ov.get("agents", {}),
            "excluded_accounts": sorted(self.excluded_accounts()),
            "schedule_b_hash": self.hashes.get("schedule_b.yaml", ""),
        }

    @property
    def charter_hash(self) -> str:
        return hashlib.sha256(self.charter_md.encode("utf-8")).hexdigest()

    def prompt_hash(self, seat_id: str) -> str:
        """Hash of preamble + seat prompt, i.e. of what the seat would actually be given."""
        pre = self.prompts.get("_preamble", "")
        body = self.prompts.get(seat_id)
        if body is None:
            return ""
        return hashlib.sha256((pre + "\n\n" + body).encode("utf-8")).hexdigest()


def load_config(config_dir: Path) -> Config:
    d = Path(config_dir)
    files = {
        "schedule_b.yaml": d / "schedule_b.yaml",
        "schedule_c.yaml": d / "schedule_c.yaml",
        "registry.yaml": d / "registry.yaml",
        "charter.md": d / "charter.md",
        "copy/public.yaml": d / "copy" / "public.yaml",
        "copy/legal.yaml": d / "copy" / "legal.yaml",
        "copy/kill_list.yaml": d / "copy" / "kill_list.yaml",
    }
    missing = [k for k, p in files.items() if not p.exists()]
    if missing:
        raise FileNotFoundError(f"config files missing in {d}: {missing}")
    prompts: dict[str, str] = {}
    prompts_dir = d / "prompts"
    if prompts_dir.is_dir():
        for p in sorted(prompts_dir.glob("*.md")):
            prompts[p.stem] = p.read_text(encoding="utf-8")
            files[f"prompts/{p.name}"] = p
    cfg = _read_config(d, files, prompts)
    require_distinct_seats(cfg)
    return cfg


def require_distinct_seats(cfg: Config) -> None:
    """Refuse a Schedule C whose seats are not each one identity (`seat_conflicts`), with one kind of error
    whatever is wrong with it. Called when the config is loaded, and again by `build_context` once the
    keyfile has said which accounts the company holds, since a seat must not be one of those either."""
    try:
        conflicts = seat_conflicts(cfg)
    except (KeyError, TypeError, AttributeError) as e:   # a seat that is not a mapping, or has no id, or a number for one
        raise ValueError(f"schedule_c.yaml: a seat entry is malformed ({type(e).__name__}: {e})") from e
    if conflicts:
        raise ValueError("schedule_c.yaml: " + "; ".join(conflicts))


def seat_conflicts(cfg: Config) -> list[str]:
    """Every seat is one identity: its id, its page handle, its key and its account each name that seat and
    no other. Everything that resolves a seat takes the first match (`seat_by_key`, `seat`, `seat_page`) and
    everything that counts seats counts the list (thresholds, quorum of members), so two seats sharing an
    identity leave one that is counted and can never act, or two people signing into one slot, and nothing
    says so (XE-2073). A Schedule C like that is refused at load, by the API, the worker and the CLI alike,
    since all three come through `load_config`. A blank key or account is a seat not yet filled, not a
    conflict.

    An id is the seat's handle everywhere (its page, the log, a stored signature), so it is there, and it
    is lower-case letters, digits and hyphens: `seat_page` looks a seat up by the lower-cased path, and an
    id it cannot spell is a seat with no page. An agent seat's page is also reached by its role, so the
    role has to make a handle. And a seat's account is not one of the company's own (treasury, fee, dao):
    those are excluded from every vote and are what the harness itself signs as, so a seat on one of them
    is two identities in one account."""
    out: list[str] = []
    handles: dict[str, str] = {}
    keys: dict[str, str] = {}
    accounts: dict[str, str] = {}
    hex64 = re.compile(r"[0-9a-f]{64}")

    def claim(taken: dict[str, str], value: str, seat: str, what: str) -> bool:
        if value and taken.setdefault(value, seat) != seat:
            out.append(f"{what} {value[:16]} is used by both {taken[value]} and {seat}")
            return False
        return True

    def handle(seat_id, seat: str) -> bool:
        if not isinstance(seat_id, str) or not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", seat_id):
            out.append(f"{seat}: id must be lower-case letters, digits and hyphens")
            return False
        return claim(handles, seat_id, seat, "seat id")

    for name, account in sorted(cfg.accounts.items()):
        accounts.setdefault(account, f"the company's {name} account")   # two names for one company account is not a seat's business
    accounts.pop("", None)
    for i, h in enumerate(cfg.human_seats):
        seat = f"human seat {i + 1} ({h.id})"
        handle(h.id, seat)
        if h.public_key and not hex64.fullmatch(h.public_key):
            out.append(f"{seat}: public_key is not 64 hex characters")
            continue
        if claim(keys, h.public_key, seat, "public key"):   # a shared key is a shared account; said once
            claim(accounts, h.account, seat, "account")
    for i, a in enumerate(cfg.agent_seats):
        seat = f"agent seat {i + 1} ({a.id})"
        handle(a.id, seat)
        if not a.slug:
            out.append(f"{seat}: role is blank, so the seat has no page")
        elif a.slug != a.id:
            claim(handles, a.slug, seat, "seat page")
        if a.account and not hex64.fullmatch(a.account):
            out.append(f"{seat}: account is not 64 hex characters")
            continue
        claim(accounts, a.account, seat, "account")
    return out


def _read_config(d: Path, files: dict[str, Path], prompts: dict[str, str]) -> Config:
    return Config(
        dir=d,
        schedule_b=_load_yaml(files["schedule_b.yaml"]),
        schedule_c=_load_yaml(files["schedule_c.yaml"]),
        registry=_load_yaml(files["registry.yaml"]),
        charter_md=files["charter.md"].read_text(encoding="utf-8"),
        copy_public=_load_yaml(files["copy/public.yaml"]),
        copy_legal=_load_yaml(files["copy/legal.yaml"]),
        kill_list=_load_yaml(files["copy/kill_list.yaml"]),
        hashes={k: _sha256_file(p) for k, p in files.items()},
        prompts=prompts,
    )


# ---- copy lint -------------------------------------------------------------------------------

def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _flatten_strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _flatten_strings(v)]
    return []


def lint_public_copy(cfg: Config, extra_texts: list[str] | None = None) -> list[str]:
    """Return a list of violations (empty means clean)."""
    phrases = [p.lower() for p in cfg.kill_list.get("phrases", [])]
    words = [w.lower() for w in cfg.kill_list.get("words", [])]
    texts = _flatten_strings(cfg.copy_public) + list(extra_texts or [])
    violations: list[str] = []
    for t in texts:
        low = t.lower()
        for p in phrases:
            if p in low:
                violations.append(f"phrase {p!r} in: {t[:80]!r}")
        for w in words:
            if re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", low):
                violations.append(f"word {w!r} in: {t[:80]!r}")
    return violations
