# What the DAO harness needs from mainnet XE

Grounded in what the code calls (`xe/client.py`, `dao/chainops.py`, `dao/services/*`, `dao/context.py`), not in what
the brief hopes for. Short version: mainnet needs to be testnet-0005's API and wire format, with the DAO keyset in
genesis and a node URL we trust. Everything else is config.

Written 27 October 2026 against `dao` commit `c60cf81`.

## 1. A node API endpoint the harness can reach

One `XE_NODE_URL` (today `https://ldn.core.test.network`). It must be reachable from the VPS, serve HTTPS, and be a
node the DAO is happy to trust for reads. Every chain fact the harness reports comes from this one node; it does not
cross-check against a second. For mainnet this should be a node we run or Adam runs, not a public third-party node.

## 2. Read endpoints, with the same shapes as testnet

| Endpoint | Used for |
|---|---|
| `GET /`, `GET /node` | `network_id`, `pow_difficulty`, `chat_pow_difficulty`, node peer id. The mainnet badge shows only when `network_id` is `mainnet` or `mainnet-<n>`; anything else shows testnet. |
| `GET /health`, `GET /network/readiness` | worker health, `/v1/ready` |
| `GET /accounts/{a}/balance`, `GET /accounts/{a}/chain` | voting weight at snapshot, treasury read, fee account frontier, agent account checks |
| `GET /accounts/{a}/keyset` | treasury multisig read |
| `GET /pending/{a}` | pending sends into the fee account (receive step) |
| `GET /blocks/{hash}` | fee verification. Must carry `finalized`; see [xeprotocol/xe#55](https://github.com/xeprotocol/xe/issues/55). |
| `GET /statechain/tip`, `GET /statechain/blocks`, `GET /statechain/blocks/{i}` | signing sessions build at the live tip; anchor verification |
| `GET /statechain/kv`, `GET /statechain/kv/{key}` | reading `dao.registry`, `dao.anchor.<n>`, `sys.*` |
| `GET /statechain/keyset` | the DAO keyset and threshold shown on `/records` and `/members`, and used to decide when a signing session has enough signatures |
| `GET /directory/{account}` | whether the DAO account is registered |
| `GET /chat/auth/challenge`, `GET /chat/messages`, `GET /chat/events` | inbox |

## 3. Write endpoints

- `POST /blocks/send`, `POST /blocks/receive`, `POST /blocks/burn`: fee refunds, receiving fees, burning fees below
  quorum. Signed by the harness's own `fee` key; PoW at the node-advertised `pow_difficulty`.
- `POST /statechain/blocks`: keyset-signed blocks for `dao.registry`, `dao.anchor.<n>`, protocol parameters. The
  harness only submits; it never holds a keyset key.
- `POST /directory/register`, `POST /chat/send`: DAO account identity and replies.

## 4. Wire-format invariants

These are what the byte-exact fixtures in `tests/test_xe_wire.py` pin to testnet-0005. If mainnet changes any of
them, the harness produces invalid hashes or signatures:

- Account address = `sha256("xe/account/v1" || pubkey)`; ed25519 throughout.
- Block canonical encoding, hash, and PoW scheme (SHA-256 + BLAKE2b, leading-zero difficulty).
- State-chain block hashing: values hashed as the exact bytes received, not canonicalised (BRIEF §16.19).
  `normalise_ops` depends on this.
- Chat envelope format and PoW; directory registration format.
- `finalized` semantics on blocks.

If any of these differ at Genesis, re-run the fixture tests against a mainnet node and fix before the first write. An
afternoon if the shapes hold; this is the main technical risk.

## 5. Genesis state the DAO needs to exist

- A DAO keyset installed in the state chain at genesis: `/statechain/keyset` non-empty, threshold at least 2, holding
  the members' keys. Without it nothing under `dao.*` can be written and `/records` shows an error.
- The `dao.*` prefix writable by that keyset, and `sys.*` if the DAO is to set protocol parameters.
- `sys.oracle` writing `epoch.<n>` blocks as on testnet is fine; the two-step signing session handles the tip race
  (BRIEF §16.15).

## 6. Accounts to fund after Genesis

Three harness accounts from `dao keys init` (`harness`, `dao`, `fee`), plus one agent account per seat later. Each
needs enough XE to publish a first block (so it exists on chain) and to register in the directory; `fee` needs enough
to pay refunds. Chat is PoW not fee, so talking costs nothing. The treasury multisig is a separate hash-derived account
with human keys only; the harness only reads it.

## 7. Nice-to-haves to raise with Adam, none blocking

- A parent-independent way to sign a state-chain block (sign over ops plus a nonce, or a reserved next index) would
  collapse signing sessions to one step (BRIEF §16.15).
- A documented `finalized` guarantee on `GET /blocks/{hash}`: what final means and whether it can flip back, since fee
  verification is about to depend on it.
- Mainnet's `network_id` to be `mainnet` or `mainnet-<n>`; the harness only shows the mainnet badge on a positive
  match, so any other name would show as testnet.
