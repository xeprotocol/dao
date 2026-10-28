"""Process-wide context: settings, config, signer, chain client, event log, node identity."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from xe.client import XeClient
from xe.pow import CHAT_POW_DIFFICULTY, DEFAULT_DIFFICULTY, parse_difficulty

from .config import Config, load_config
from .log import EventLog
from .settings import Settings, get_settings
from .signer import Signer, SignerError

log = logging.getLogger("dao")


@dataclass
class NodeIdentity:
    network_id: str = ""
    node_id: str = ""
    version: str = ""
    pow_difficulty: int = DEFAULT_DIFFICULTY
    chat_pow_difficulty: int = CHAT_POW_DIFFICULTY

    @property
    def is_mainnet(self) -> bool:
        """Positive match only: `mainnet` or `mainnet-<n>`. Anything else (testnet-0005, devnet, unknown, empty)
        is shown as testnet, so a renamed or unexpected network can never be mistaken for the real one."""
        return self.network_id.split("-", 1)[0] == "mainnet"

    @property
    def badge(self) -> str:
        return "mainnet" if self.is_mainnet else "testnet"


@dataclass
class Context:
    settings: Settings
    config: Config
    signer: Signer
    chain: XeClient
    events: EventLog
    node: NodeIdentity = field(default_factory=NodeIdentity)

    async def refresh_node(self) -> NodeIdentity:
        try:
            info = await self.chain.node()
        except Exception as e:  # node unreachable at boot is survivable
            log.warning("node unreachable: %s", e)
            return self.node
        self.node = NodeIdentity(
            network_id=info.get("network_id", ""),
            node_id=info.get("id", ""),
            version=info.get("version", ""),
            pow_difficulty=parse_difficulty(info.get("pow_difficulty"), DEFAULT_DIFFICULTY),
            chat_pow_difficulty=parse_difficulty(info.get("chat_pow_difficulty"), CHAT_POW_DIFFICULTY),
        )
        return self.node

    @property
    def directory_node_peer(self) -> str:
        return self.settings.directory_node_peer or self.node.node_id

    async def aclose(self) -> None:
        await self.chain.aclose()


_ctx: Context | None = None


def build_context() -> Context:
    settings = get_settings()
    config = load_config(settings.config_dir)
    try:
        signer = Signer.load(settings.signer_keyfile, settings.signer_passphrase)
    except SignerError as e:
        log.warning("signer unavailable (%s); running without company keys", e)
        signer = Signer.empty()
    chain = XeClient(settings.xe_node_url)
    events = EventLog(signer)
    return Context(settings=settings, config=config, signer=signer, chain=chain, events=events)


def get_context() -> Context:
    global _ctx
    if _ctx is None:
        _ctx = build_context()
    return _ctx


def set_context(ctx: Context) -> None:
    global _ctx
    _ctx = ctx
