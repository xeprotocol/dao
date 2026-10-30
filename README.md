# XE DAO

The operating harness for XE Network DAO LLC. Humans and agents propose, analyse, decide, sign and publish; the XE chain is the memory and the signature.

- Brief: [`docs/BRIEF.md`](docs/BRIEF.md)
- Deploy: [`docs/DEPLOY.md`](docs/DEPLOY.md)
- Mainnet requirements: [`docs/MAINNET_REQS.md`](docs/MAINNET_REQS.md)
- Licence: GPL-3.0-or-later

## What version 1 does

- **Articles-facing surface** under `/v1/legal/*`: identifier, registry, keyset, reserved matters, schedules, resolutions, pause, treasury, anchors. Stable paths, legal vocabulary, read-only.
- **Public portal**: anyone proposes for a 10 XE fee, anyone with XE votes. Weight is the XE balance at the open snapshot; quorum is **20 participating wallets**, not an XE amount. Open votes are not self-executing: a closed vote becomes a decision item the DAO answers with reasons.
- **Members-direct operations**: resolutions (ordinary = majority, reserved = all members), two-step state-chain signing sessions (approve the ops, then sign a block at the live tip), pause (72 h by one member on a written determination; 7-day extensions jointly; public post within 4 h, auto-published), inbox replies, signed public notes.
- **Ledger of record**: a hash-chained, signed event log (`/v1/log`, `/v1/log/verify`, `/v1/events` SSE with `event: entry` per log entry and `/live` as its human view) anchored weekly to the state chain under `dao.anchor.<n>`.
- **The ensemble, explained before it runs**: `/seats` lists every agent seat; `/seats/<role>` (e.g. `/seats/legal-and-compliance`) carries its summary, scopes, status and full instructions with hashes; `/how-it-works` describes the debate order and how seats exchange records; `/decisions/example` renders a worked decision record from `config/examples/` so the artefact's shape is public before any seat is switched on.
- **Readable by agents**: every page has a markdown twin at the same path with `.md` appended (`/seats/research.md`; the home page is `/index.md`), or on `Accept: text/markdown`. Rendered from the same HTML on the way out, so no page can drift from its mirror. `/llms.txt` is the reading list.
- **Chain presence**: the DAO's own account is directory-registered, receives chat, acknowledges every message, and replies from the same account. Fees are received into a dedicated fee account and refunded or burned per the pinned rules.

The harness holds three company keys (`harness`, `dao`, `fee`) in an encrypted keyfile with fixed scopes. It holds **no** keyset key, **no** treasury key, **no** member key. Those live with people and sign in the browser (WebCrypto Ed25519) or offline (`dao sign`).

## Layout

```
xe/        protocol wire formats: addresses, blocks, PoW, state chain, chat, directory, HTTP client
dao/       the harness: settings, config-as-data, event log, signer, services, API, UI, worker, CLI
config/    Schedule B, Schedule C, registry, charter, copy registers (public / legal / kill list)
alembic/   database migrations
tests/     byte-exact fixtures from the live testnet + harness unit tests
docs/      DEPLOY.md
```

## Signing convention

Every write is a `SignedRequest`:

```json
{"payload": {...}, "timestamp": <unix ns>, "pub_key": "<hex>", "signature": "<hex>"}
```

`signature = ed25519( sha256( domain || 0x00 || canonical_json({"payload": payload, "timestamp": timestamp}) ) )` with `canonical_json` = sorted keys, no whitespace, ASCII-escaped. Domains: `xe-dao/proposal/v1`, `xe-dao/vote/v1`, `xe-dao/inbox/v1`, `xe-dao/member-action/v1`, `xe-dao/resolution/v1`, `xe-dao/ops-approval/v1`. The account is derived from the key (`sha256("xe/account/v1" || pubkey)`). Timestamps must be within ±10 minutes; a signature is accepted once (the claim is stored in the database in the same transaction as the write it authorised, so it survives restarts). A replacement vote must carry a later timestamp than the one on record. Free-text fields refuse control characters other than tab, newline and carriage return. Public write routes are rate-limited per IP and per account (429 with `Retry-After`).

`POST /v1/inbox` additionally requires `"pow_nonce": <u64>` with `sha256(nonce_le8 || signing_digest)[0:8]`, read big-endian, `>=` the difficulty the node advertises for chat (`GET /v1/inbox` shows it). The receipt is kept in the hash chain but appears on the public log only once a member has read the message. Proposal fees must be `finalized` on the chain before they are accepted, and a fee that was never received into the fee account is parked as `unreceived` rather than refunded or burned.

```sh
dao sign-request xe-dao/vote/v1 '{"proposal":"<hash>","choice":"for","reason":""}' --seed <hex> \
  | curl -s -X POST https://dao.test.network/v1/votes -H 'content-type: application/json' -d @-
```
