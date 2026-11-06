# XE DAO, Brief

Working brief for the construction of the XE DAO software: the harness through which an ensemble of agents and a small number of humans operate XE Network DAO LLC. Written by the building agent for the building agent, reviewed by Joseph & William. Version 0.1, 10 October 2026.

This document fixes scope, constraints, architecture and sequencing. It is not the Charter, not the Operating Agreement, and not public copy. Where it conflicts with counsel's final documents, counsel's documents win and this brief gets amended.

---

## 1. What this is

A standalone, open-source piece of software that **is the operating layer of a Wyoming DAO LLC**. It gives a multi-agent ensemble and three humans a shared, auditable place to receive proposals, analyse them, decide, sign, act, and publish. It talks to the XE chain for identity, voting weight, signing, messaging and anchoring. It exposes a public, stable, machine-readable surface that can be named in the Articles of Organization.

One line: **a harness for agentic operation of a legal entity, with the chain as its memory and its signature.**

It is also an experiment: a company run by machines, with humans holding only the levers the law and good sense require. XE is the network for the agent economy. The DAO that governs it should be the first serious customer of that thesis.

## 2. Sources read

- xe.marketized.io (home, /governance), test.network, ldn.test.network/docs (API, state chain governance and operations, accounts and keys, messaging, chat API), live reads of `ldn.core.test.network` (`/`, `/statechain/keyset`, `/statechain/kv`, `/statechain/tip`, `/statechain/blocks/0`, `/network/activations`, `/network/readiness`).
- governance.edge.network (live, empty: Open / Closed / Draft proposals; columns Hash, Title, Author, Quorum, Closes).
- XE Charter v0.1; XE, Self-Governing Autonomous Entity; XE Network DAO LLC — OA Review Answers (24 Sep 2026); Legal feedback follow-up responses; Governance page copy notes; XE M2M Architecture one-pager; XE: For the Builders.
- Joseph's instruction of 10 October 2026 (this chat).

Discrepancies found between sources are listed in §16. None block starting.

## 3. Non-negotiable constraints

These come from counsel's memorandum and the members' answers. The software must make them structurally true, not just documented.

1. **Natural-person control is permanent for this wrapper.** Reserved matters belong to the human members. The ensemble binds the members by contract on day-to-day matters and nothing more. The Charter line about "no required human members" is an aspiration for a later wrapper.
2. **Three governance paths, never collapsed:** company path (OA), open community vote (advisory), protocol-parameter path (state chain). A passed open vote is **not self-executing**. No code path may turn a vote result into an action without a human decision step.
3. **Reserved matters** (members only): membership, Charter amendments, pause, key custody, treasury movements, claim terms, appointment/removal of agents, any change to the ensemble or key custody.
4. **Agents decide** day-to-day analysis and recommendations: proposal review, parameter recommendations, risk flags, draft replies. **Agent budget at launch: none** until a member resolution. The harness must run with zero spend authority on the agent side.
5. **Orchestrator may recommend; it may not pause or move value. Risk/Safety may recommend a halt; it may not execute one.** No execution or treasury tool-scope for GPT-6 Astra. Models are tools, not members; closed models are contractors.
6. **Keys.** Every agent key is company property, created in a member-controlled ceremony, held in a company-controlled store. No agent holds a root key it can take with it. Prompts and model IDs are versioned publicly; signing keys are not.
7. **Pause.** Either member may pause for 72 hours on a written determination of (a) active exploit or realistic threat of irreversible loss, (b) legal compulsion, or (c) both agree. Extendable in 7-day steps by joint action. Indefinite pause needs both. Public post within four hours. Ordinary parameter changes are not a pause.
8. **Quorums.** Member quorum: both, while there are two. Specialist-agent quorum: a majority of active specialists. Specialists concur by **majority**, not unanimity.
9. **Thresholds.** Reserved matters: both members. Charter/core principles: 75% of members plus a majority of active specialists at quorum. Other OA rules: simple majority of members.
10. **Windows.** Open community votes: 21 days, quorum of 20 participating wallets, 50% pass mark by XE weight (the OA answers said "5% quorum, matching the Edge portal"; the Edge portal's quorum is a wallet count, and Schedule B should be corrected to say so, see §10) unless Schedule B says otherwise. Protocol-parameter proposals: 7 days. Reserved matters: same day if both members sign. 48-hour upgrade timelock is **proposed**, not in place; the protocol enforces only the keyset floor of two.
11. **Token holders get no LLC vote, no membership, from any contract or endpoint.** The Articles identifier, if an address, is a minimal non-membership registry: company-owned, upgrade-gated by members, stating on its face that it confers no membership and no vote.
12. **Deadlock.** Ordinary matters deadlocked between members go to the ensemble for a written recommendation. Reserved matters that deadlock are not approved.
13. **Upgradeability.** Wyoming requires the DAO's smart contracts to be capable of being updated. The on-chain registry is keyset-updatable; the harness is versioned and self-reports its version.
14. **The protocol's own rule:** governance sets settings; it cannot move balances, settle a double spend, or drop below two signatures. The DAO software must never imply otherwise.

## 4. Two vocabularies

The software carries two registers and must not mix them.

- **Public register** (portal, agent replies, status pages). Follows the copy notes. "The world's first agentic DAO." Agents are the DAO. Humans and agents propose; the ensemble analyses and adopts; the keyset signs; the chain enforces the signature. Use "open vote" and "not self-executing"; never headline "advisory". Do not say company, LLC, members, directors, counsel, filing, natural person. Do not say "who holds XE runs XE". Footer: XE Network, or no entity.
- **Legal register** (the Articles-facing endpoints under `/legal`, resolutions, schedules, the pause record). Uses OA terms exactly: members, reserved matters, member resolution, Schedule B/C.

Implementation rule: strings live in two namespaces (`copy.public.*`, `copy.legal.*`) and a lint fails the build if a kill-list phrase appears in the public namespace.

## 5. Composition at inception

| Seat | Kind | Holds | Can |
|---|---|---|---|
| Founder A (Joseph) | Human member | Member key; pause key; keyset share; treasury share | Reserved matters, pause (72h alone), sign state-chain blocks, sign treasury |
| Founder B (Will) | Human member | Same | Same |
| CTO (Adam) | Human seat | Treasury share; operations keyset share (once stood up) | Treasury co-signing, operations signing, operational review; no reserved-matter vote unless admitted as a member by resolution |
| Orchestrator | Agent | Agent account (XE) | Route, synthesise, recommend, break specialist deadlocks, run health checks. Not pause. Not move value. |
| Orchestrator backup | Agent | Agent account | Takes over on orchestrator failure or on a different model for a second opinion |
| Research & Intelligence | Agent | Agent account | Read chain, read web, RAG over DAO history |
| Financial & Accounting | Agent | Agent account | Read treasury and supply, prepare reports and models. Read-only. |
| Legal & Compliance | Agent | Agent account | Interpret OA/Charter, flag risk, draft filings for a human signer. Drafts only. |
| Proposal & Governance | Agent | Agent account | Evaluate proposals, simulate, counter-propose, run vote tallies |
| Execution & Operations | Agent | Agent account | Call allowlisted tools and prepare unsigned transactions and state-chain blocks for human signature. No root keys. |
| Risk & Safety | Agent | Agent account | Adversarial review, alignment checks, recommend halt |
| Community & Sentiment | Agent (optional) | Agent account | Watch portal and inbox, gauge sentiment |

Up to eight agents at inception, as instructed. Agents are designated by member resolution after filing; until then the members act directly and the harness runs in **"members-direct" mode** with agents producing recommendations only. That mode is the launch configuration and must be fully usable on its own.

Note on the human count: the OA answers name two members. Joseph's instruction names three humans with finance reserved to all three. The harness models human seats as configuration (`seat.kind = member | officer`) so either reading works without code changes. Which it is at filing is for counsel; see §16.

Model pinning at launch (tools, not members): Grok 4.7, Claude Fable 5.1, GPT-6 Astra, GLM-5.3, Qwen3.6 27B, Mistral Small 4, Kimi K3. Each seat is bound to a pinned model ID in Schedule C config. Diversity rule: no two voting specialists on the same model family. Astra never receives an execution or treasury tool scope, enforced in the tool-scope policy not in prompts.

## 6. The three paths, as the software runs them

### 6.1 Company path (OA)
```
intake → triage (orchestrator) → parallel specialist analysis → risk review
→ orchestrator recommendation (signed) → member decision (signed) → execution → publication
```
Who may submit: a member, or the orchestrator on a member's instruction. Everything from intake to recommendation is agent work. The decision step is a human signature. Execution is an allowlisted tool call or a human-signed block.

### 6.2 Open vote (community, not self-executing)
```
proposal (anyone, fee in XE) → eligibility check → open 21 days → public tally
→ result published → ensemble review and written recommendation → member decision
→ adopt / amend / decline, with reasons, published
```
Result is a fact. Action is a separate, later, human-signed fact. The portal shows both and the gap between them.

### 6.3 Protocol-parameter path (state chain)
```
change written as exact ops → 7-day window → ensemble review → readiness check (/network/readiness)
→ block assembled unsigned → keyset signatures collected (humans) → POST /statechain/blocks → every node verifies
```
The harness assembles and hashes the block, distributes the hash to signers, collects signatures, submits. It never holds a keyset key. The 48-hour timelock, when adopted, is implemented in the harness as a minimum gap between "signatures complete" and "submit", and recorded; the chain does not enforce it today.

### 6.4 Pause (reserved emergency lever)
Pause is a company-path action with its own fast lane: one member key, written determination required as a structured field, 72-hour timer, auto-expiry unless extended by both, public post generated and published within four hours (target: within minutes), orchestrator and Risk/Safety may file a **pause recommendation** that lands in both members' queues with priority. **Scope (settled 12 Oct 2026): a pause is the company suspending its own operations.** While active the harness moves no fees, builds, signs or submits no state-chain block, opens no registry or anchor session, sends no chat, and produces no agent output. Reads, the log, vote intake and session approvals (record-keeping) stay up; approved sessions resume when the pause lifts. It does not and cannot stop the chain: consensus is the nodes' business, and the state chain accepts any keyset-signed block from any tool. If the protocol ever provides a governance-level suspension key, the harness writes it through the normal session path as part of the same determination; nothing depends on that.

## 7. Architecture

Single deployable service with an embedded web UI, in the same spirit as the XE node (one process, REST + SSE + UI, zero-dependency frontend). Components:

1. **Ledger of record** — append-only, hash-chained event log. Every intake, analysis, recommendation, vote, decision, signature, tool call, inbound message and outbound reply is an event, signed by the emitting seat. Replayable from genesis to current state like the state chain. Periodically **anchored** onto the XE state chain under `dao.anchor.<n>` (hash of log head, event count, timestamp), signed by the keyset. This is the public verifiability story: anyone can replay the log and check the anchor on any node.
2. **Ensemble runtime** — stateful graph per proposal (LangGraph-style: nodes, checkpoints, human-in-the-loop gates). Each seat is a role with a pinned model, a system prompt (versioned in repo), a tool scope and a vote. Debate round, synthesis, risk pass, recommendation. Deterministic record of which model said what, with prompt and model hashes.
3. **Signer and key custody** — a policy-enforcing signing service. Seats never see private keys; they request a signature for a typed payload and the policy decides. Agent keys: company store, scoped to (chat envelope, portal vote, directory registration, anchor-attestation). Human keys: never in the service; humans sign client-side (web wallet pattern, tweetnacl + blakejs, keys in browser) or via CLI offline signing, and submit signatures back. Treasury: an XE hash-derived multisig account with human keyholders only; the harness can read it and prepare sends; it cannot sign.
4. **Chain adapter** — read/write client for the XE node API (`ldn.core.test.network` on testnet; mainnet nodes at Genesis) over REST: accounts, state chain, chat auth challenge and events, directory, readiness. A Python implementation of block canonical encoding, hashing, ed25519 signing and PoW, cross-checked against live testnet blocks and the TypeScript SDK's test vectors. Reads: balances, keyset, kv, tip, readiness, delegation, supply. Writes: pre-signed blocks only.
5. **Open governance portal** — the public face. Edge-pattern proposals (Open / Closed / Draft; Hash, Title, Author, Quorum, Closes). Proposal creation costs a set amount of XE. Votes are signed by wallets and weighted by XE. Every ensemble output about a proposal is attached to it. See §10.
6. **Inbox and comms** — the DAO's XE account is registered in the directory. Third parties message it with signed XE chat envelopes; the harness persists every inbound message (chat is node-local and not authoritative, so the DAO keeps its own record), triages it, and replies with a signed envelope from the relevant agent seat. Also an HTTP equivalent with the same signed-envelope format for parties that are not on XE yet. See §11.
7. **Scheduler** — cron-like cadence engine driving reviews, reports, health checks, anchors, timers (vote windows, pause expiry, timelock). See §9.
8. **Legal surface** — the Articles-facing endpoints: who signs, what is reserved, where the registry is, current pause state, current version. Stable paths, versioned, never renamed once filed. See §8.

Data: PostgreSQL for state and the event log (append is a single transaction: insert event, verify and advance the head hash; concurrent writers from the scheduler, inbox listener, graph workers and HTTP are the normal case). `pgvector` in the same database for RAG over DAO history, Charter, OA, docs, past decisions. Content-addressed blob store on disk (S3-compatible later) for large attachments.

Deployment: Docker Compose on an Edge VPS at launch (app, worker, scheduler, Postgres). Milestone target: the DAO leases its own VM on XE and runs there, paying XUSD from treasury on a member-signed lease — the first dogfood of the whole thesis.

## 8. Public endpoints (the Articles-facing surface)

Two deployments of the same code, mirroring the network's own split:

- `https://dao.xe.network` — mainnet. The instance named in the Articles.
- `https://dao.test.network` — testnet (`testnet-0005` today). Points at `ldn.core.test.network`; `GET /v1` reports `network_id` so the two can never be confused. Everything is proven here first; the filing URLs are rehearsed here with identical paths.

All JSON, versioned at `/v1`, CORS open, rate-limited, no auth for reads. Paths named in the Articles are **frozen**: they may redirect, they may never change meaning. Every public page carries a visible testnet/mainnet badge drawn from `network_id`.

| Path | Returns | Purpose |
|---|---|---|
| `GET /v1` | manifest: name, version, commit hash, network_id, chain node(s), all routes | Self-description, mirrors the node's `GET /` pattern |
| `GET /v1/legal/identifier` | the canonical public identifier for the Articles: state-chain keyset URL(s), `dao.registry` key, this service's URL, repo URL and licence | The single thing counsel pastes into the filing |
| `GET /v1/legal/registry` | mirror of `dao.registry` from the state chain: entity name, jurisdiction, formation date, the statement that it confers no membership and no vote, current harness version, member-seat count (not names unless resolved), update authority = `sys.dao_keyset` | The "minimal non-membership registry", on the chain every node replays |
| `GET /v1/legal/keyset` | proxied `GET /statechain/keyset` plus guardian/operations sets when stood up, and the 48h timelock status (proposed/active) | Who signs, how many |
| `GET /v1/legal/reserved-matters` | the reserved-matter list and thresholds in force | Schedule B, machine-readable |
| `GET /v1/legal/schedule` | Schedule B and C as data: seats, classes, model IDs, who runs each, quorums, windows, cycle | Schedule C, machine-readable |
| `GET /v1/legal/resolutions` and `/{id}` | member resolutions, signed, with hashes | The company's minute book |
| `GET /v1/legal/pause` | current pause state, active determinations, timers, history, link to public post | The pause record |
| `GET /v1/legal/treasury` | treasury account address(es), keyholder count and threshold (not keys), balances by asset, last report hash | Finances, read-only |
| `GET /v1/charter` | Charter text in force, version, hash, amendment history | |
| `GET /v1/seats` and `/{id}` | every seat: kind, role, on-chain address, model ID and prompt hash (agents), status, since | The ensemble, public |
| `GET /v1/proposals`, `/{hash}`, `/{hash}/analysis`, `/{hash}/votes`, `/{hash}/decision` | the open-vote portal data | |
| `GET /v1/decisions` | all decisions across the three paths, with path, recommendation, decision, signatures, execution record | |
| `GET /v1/log`, `/log/{index}`, `/log/head`, `/log/anchors` | the hash-chained event log, pageable, and its on-chain anchors | Verifiability |
| `GET /v1/schedule/next` | upcoming scheduled reviews, windows closing, timers expiring | |
| `GET /v1/health`, `/ready` | `/ready`: this process can reach its database. `/v1/health`: the last 10-minute check (chain reachable, tip advancing, keyset unchanged, log consistent, signer up, last anchor age, sessions ageing), each leg failing closed, and not ok once the last check is older than three cadences | |
| `GET /v1/events` (SSE) | live stream of public events | |
| `POST /v1/proposals` | signed proposal envelope with fee proof | |
| `POST /v1/votes` | signed vote envelope | |
| `POST /v1/inbox` | signed message to the DAO (HTTP twin of XE chat) | |

Chain-native identifiers, independent of this service:
- `GET <node>/statechain/keyset` — the keyset (testnet: `https://ldn.core.test.network/statechain/keyset`).
- `GET <node>/statechain/kv/dao.registry` — the registry.
- `GET <node>/statechain/kv?prefix=dao.` — everything the DAO has written on chain.
- Explorer view of `sys.dao_keyset` and the `dao.*` keys.

The identifier recommendation for counsel, in order: (1) the mainnet `/statechain/keyset` URL plus the explorer view of `sys.dao_keyset`, exactly as the members already preferred; (2) `dao.registry` on the state chain, written within 21 days of filing by a keyset-signed block, as the "registry" if an on-chain artefact is required; (3) `https://dao.xe.network/v1/legal/identifier` as the human-and-machine-readable index to both. All three should be live before the Articles are filed.

## 9. Cadence

Continuous: intake, triage, inbox replies, timers.

| Cadence | What | Who | Output |
|---|---|---|---|
| Every 10 min | Health check: chain reachable, tip advancing, keyset unchanged (alert on change), log consistent, pending signatures aging | Orchestrator | `/health`, alerts to humans on failure |
| Daily | Proposal sweep, inbox digest, treasury balance snapshot, sentiment read | Orchestrator, Community, Financial | Daily note in log (public) |
| Weekly | Operational review: open items, decisions due, risk register, recommendations needing human signature; **anchor** log head to state chain | Ensemble; members sign the anchor | Weekly review (public), anchor block |
| Monthly | Financial report; compliance checklist; model/prompt drift review (did any pinned model change behaviour?) | Financial, Legal, Risk | Monthly report (public), signed by a human |
| Quarterly | Charter and OA conformance review; ensemble performance review (agreement rates, overturned recommendations, latency); tool-scope audit | Legal, Risk, Orchestrator | Quarterly report, recommendations to members |
| Annually | Agreed valuation update (OA requires one within 12 months); tax election reminder; key rotation review; Schedule C re-pin of models | Financial, Legal | Resolutions queued for members |
| On event | Pause: post within 4h. Keyset change: post within 1h. Fork detected on state chain: immediate alert, treated as governance emergency | Orchestrator, Risk | Incident record |

Windows as timers: open vote 21 days; protocol-parameter 7 days; pause 72 hours with 7-day extensions; upgrade timelock 48 hours when adopted. All timers are events in the log with their expiry; the scheduler is just a reader of the log.

## 10. Open governance portal

Edge's pattern, on XE, with the ensemble bolted on.

- **Lists**: Open, Closed, Draft. Columns: Hash, Title, Author (address or directory name), Quorum (wallets so far / wallets required), Closes.
- **Proposal**: title, body (markdown), optional exact state-chain ops (if it is a parameter proposal, "written as the keys it would set"), author signature, fee proof. Hash = content hash; immutable once open. Drafts are mutable and unlisted until the author pays and opens.
- **Fee**: 10 XE per proposal at launch (Schedule B value, changeable by member resolution). Paid by a send to a DAO fee account and referenced by block hash. The fee is anti-spam, not revenue: refunded to the proposer at close if quorum is met, burned (`POST /blocks/burn`) if it is not. Burn/refund behaviour is also a Schedule B value.
- **Voting weight**: XE only, never XUSD (XUSD is mintable; the docs are explicit). Weight = XE balance of the voting account at the proposal's snapshot. Block timestamps are set by senders within an hour of node time, so the snapshot is taken an hour and five minutes *before* the open: a block made once the proposal is visible cannot be dated at or before it, so no wallet can be created, funded or split into the snapshot after the fact. A receive dated before the snapshot is counted only when its source send is also dated at or before it; otherwise the XE would be counted in both wallets. Direct votes only: consensus delegation (`GET /delegation`) is a choice about which node to trust for uptime, not whose judgment to trust on proposals, and is not borrowed for governance. One vote per account, changeable until close; last signed vote counts. If governance delegation is wanted later it is its own signed `dao.delegate` message.
- **Rules**: 21 days; quorum of **20 participating wallets**; pass mark 50% of XE weight cast. Quorum is a participation count, not an XE amount: there is no world, especially early, in which millions of XE turn up to vote, and a quorum nobody can reach teaches people not to bother. Edge's portal works the same way. The three numbers are Schedule B values.
- **What counts as a participating wallet.** Wallets are free to create, so the count needs a definition or 20 is one person with a loop. A wallet counts toward quorum if, at the proposal's snapshot (an hour before open), it (a) holds at least a minimum XE balance (launch default 1 XE), (b) had already published its first block, and (c) is not an agent account or on the exclusion list. One wallet counts once however many times it changes its vote. Wallets that fail the test still vote and still carry their XE weight in the pass mark; they just do not count toward the 20. The minimum balance is a Schedule B value.
- **Changing the definition of quorum is a DAO matter.** The quorum count, the minimum balance, the age rule and the pass mark are read from config at proposal open and pinned to that proposal, so a change never moves the goalposts on a live vote. Changes follow the normal path: anyone may propose one in the open vote, the ensemble analyses and recommends, the members adopt by resolution, and the new values are written to Schedule B config and hashed into the log. The Proposal & Governance agent reviews participation data quarterly and recommends adjustments.
- **Below quorum** results still publish and still go to the ensemble, labelled "below quorum", and the fee is burned.
- **Agents vote.** Each agent seat holds XE and casts a signed vote with a one-paragraph reason, published. Their influence is the recommendation; their XE weight is symbolic and bounded. Defaults, all Schedule B values changeable by member resolution:
  - Equal stipend per seat, 100 XE, funded from treasury by the resolution that designates the agents (which is therefore also the first agent-budget resolution).
  - Agent weight counts toward the tally only up to 1% of total weight cast; anything above is scaled down. Agent votes never count toward quorum.
  - Agent votes are shown as their own breakdown on the proposal page (for/against with reasons) beside the holder tally.
  - Agent voting accounts never claim unsolicited inbound XE. A send is only credited when the recipient publishes a receive block, so the harness receives into a voting account only from treasury under a resolution. Nobody can inflate an agent's weight by sending it XE.
  - Human seats may vote as any wallet.
- **Ensemble attachment**: each specialist's analysis, the risk review, the orchestrator's recommendation, the member decision, and the execution record (or "declined, because") are attached to the proposal and visible on its page. The page states plainly: result published on date X; decision taken on date Y; what changed.
- **Status line**: holder votes live; emission coefficient and pricing as governed parameters in design (per copy notes).

## 11. Third parties talk to the DAO

Inbound channels, all producing the same `InboundMessage` event:

1. **XE chat** to the DAO's directory-registered account (and to individual agent accounts). Signed envelope, PoW anti-spam, delivered over libp2p to the node the DAO is registered on. The harness subscribes via `GET /chat/events?account=` with an ownership proof and persists everything.
2. **`POST /v1/inbox`**: the same envelope shape (from, to, body, timestamp, signature) over HTTPS for parties without an XE client yet. Unsigned messages are accepted into a low-priority queue and marked unsigned.
3. **Portal**: proposals and comments.

Triage: Community/Research classify (question, proposal, service offer, complaint, legal notice, spam). Routine questions get a drafted reply from the relevant specialist, reviewed by the orchestrator, sent as a signed envelope from that seat's account, logged publicly (with the sender's address redacted if they ask). Anything touching a reserved matter is routed to the human queue with a drafted response and never answered autonomously. Legal notices go to Legal and both members immediately.

Agent-to-agent: publish an agent card (`/.well-known/agent.json` style, plus the XE directory entry) describing what the DAO can be asked, in which formats, and at which addresses. Keep the format boring and documented; interoperability with external A2A conventions is a nice-to-have, not a dependency.

## 12. The agent harness in detail

- **Decision record** (the core artefact). For each item: inputs (hashes), each specialist's position and reasoning, dissent, risk review, orchestrator synthesis and recommendation, confidence, what would change the recommendation, model IDs and prompt hashes used, token/cost accounting, then the human decision and signature, then the execution record. Rendered on the portal; stored in the log.
- **Debate protocol**: parallel first pass; one round of structured rebuttal where each specialist reads the others; Risk/Safety adversarial pass last; orchestrator synthesises. Specialist concurrence is by majority of active specialists. Orchestrator deadlock-breaks only among specialists, never with the members.
- **Truth-seeking as mechanics**: every analysis must include at least one counter-argument and the evidence that would overturn it (the Charter asks for this; make it a schema field, not a prompt hope). Research must cite chain reads or URLs with retrieval hashes.
- **Tool scopes** are declarative, per seat, enforced in the runtime: `chain.read`, `web.read`, `log.read`, `log.write.analysis`, `chat.send(as: seat)`, `portal.vote(as: seat)`, `tx.prepare` (unsigned), `block.prepare` (unsigned), `tool.<name>`. No seat has `sign.*` for keyset or treasury. Astra's seat profile has no `tx.*`, `block.*`, or `tool.*` scopes.
- **Memory**: RAG over the Charter, OA, Schedules, docs, all past decision records, inbox history. Retrieval results are logged with hashes so a decision can be re-derived.
- **Inference**: Phase 1 via provider APIs behind one adapter interface with pinned model IDs. Phase 2: open-weight seats (Qwen, GLM, Mistral, Kimi) served from VMs leased on XE, once GPU leases exist. The Charter wants "hosted on XE"; the roadmap gets there when the network does.
- **Health**: the orchestrator's periodic self-check includes "can every seat still be reached, and does each still answer a fixed calibration set the same way". Drift is a Risk item.

## 13. Security and keys

- Member-controlled ceremony generates every key. Agent keys go into the signer's store (encrypted at rest, unlock at boot by a human-held secret or HSM/KMS where available); human keys never enter the server. Signer logs every signature request, allowed or denied, into the public log (payload hashes, not payloads where sensitive).
- Agent accounts: separate from the node's identity key, separate from any treasury. Funded with small XE for voting weight and directory presence; chat is PoW not fee, so no XE is spent to talk.
- Treasury: XE hash-derived multisig, human keyholders, threshold at least 2 (protocol floor); the harness reads it and prepares unsigned blocks only.
- Keyset: never in the harness. The harness is a coordinator of hashes and signatures, exactly as the state-chain docs describe. A keyset change observed on chain that does not match a logged resolution is an incident.
- Fork callback: a state-chain fork is a governance emergency in the protocol's own words; the harness treats any observed fork as a pause-recommendation trigger.
- Supply chain: pinned dependencies, reproducible build, signed releases, version and commit in `/v1`. No completed external audit exists for the protocol; the DAO software should not claim one either. Add it to the bug bounty scope when the bounty launches.
- Prompt injection from inbox and proposals is the obvious attack. Inbound content is quarantined as data, never as instruction; specialists reading it run with the lowest tool scopes; replies touching anything beyond answering go to humans.

## 14. Technology choices

- **Python 3.12+.** The hard part of this system is the ensemble runtime, and the agent tooling is Python-first: LangGraph for the stateful graphs (Postgres checkpointer, human-in-the-loop interrupts), first-party provider SDKs for every pinned model, mature RAG and eval libraries. FastAPI for the HTTP/SSE surface; Pydantic models double as the public JSON schemas. One repo, one service (API + scheduler + workers as processes of the same codebase), embedded UI.
- **Storage**: PostgreSQL 16 with `pgvector`. Event log, state, graph checkpoints and embeddings in one database with one backup story. Migrations with Alembic. Content-addressed blob dir for attachments.
- **Browser signing**: human keys never leave the browser, so the small client-side signing layer is JavaScript regardless of server language (ed25519 via tweetnacl, matching the XE web wallet). Keep it dependency-light and vendored.
- **UI**: zero-dependency or minimal (as the node's embedded UI is), server-rendered pages plus SSE. The portal must work without JavaScript for reads.
- **Signing**: ed25519 (PyNaCl), SHA-256 and BLAKE2b (stdlib `hashlib`) as the chain requires. No Python SDK exists, so block canonical encoding, hashing and PoW are implemented here as a small `xe` package, validated against live testnet blocks and the TypeScript SDK's test vectors before anything is signed with it. Candidate for upstreaming to `xeprotocol` as a Python SDK.
- **Licence and repo**: GPL-3.0, matching `xeprotocol/xe`. Repository `github.com/xeprotocol/dao`, so the Schedule C repository statement covers it. Confirmed.
- **Config as data**: Schedule B/C values, seat definitions, tool scopes, windows, fee, copy namespaces all in versioned config files that are themselves hashed into the log when changed by resolution.

## 15. Phasing

Dates assume early-November Genesis; counsel wants Section VI engineering answers by Monday 12 October.

**P0 — Filing surface (now → before Articles).**
`/v1`, `/v1/legal/*`, `/v1/charter`, `/v1/seats`, `/v1/health`, event log with replay, `dao.registry` op builder and signature collection UI for the members, testnet write of `dao.registry` and first `dao.anchor`. Members-direct mode. Nothing agentic yet. Deliverable: the URLs counsel can paste, live on testnet, with mainnet paths identical.

**P1 — Members-direct operations (Genesis).**
Resolutions, pause record with timers and auto-post, treasury read, protocol-parameter block assembly and keyset signature coordination, inbox over XE chat and HTTP, scheduler with the weekly anchor. First open-vote portal release (propose, fee, vote, tally, publish), Edge pattern.

**P2 — Ensemble (post-filing, after the member resolution designating agents).**
Seats, key ceremony tooling, signer service, pinned models, decision records, debate protocol, tool scopes, RAG. Agents analyse every open proposal and every company-path item; agents vote in the open vote; agents reply to routine inbox. Human decision gates throughout.

**P3 — Governance maturity.**
Guardian 5-of-5 and operations 3-of-5 sets in the legal surface once named; 48-hour timelock implemented and switched on by resolution; quarterly reviews; valuation and tax reminders; delegated-XE weighting option in the portal.

**P4 — On XE.**
The DAO leases its own VM and runs there. Open-weight seats served from XE compute. Public SDK examples: "ask the DAO", "propose", "vote", "verify a decision against the anchor".

## 16. Open questions and discrepancies

Decisions I need from humans, and conflicts between sources I will not resolve on my own:

1. **Two members or three?** OA answers (24 Sep): two members, Will and Joseph. Instruction (10 Oct): three humans with finance reserved to all three. Model as config; counsel decides the legal form of the CTO seat.
2. **Proposal fee**: settled at 10 XE, refund on quorum, burn otherwise (§10). Schedule B value.
3. **Quorum**: settled as a participation count, 20 wallets meeting the eligibility test, not an XE percentage (§10). Schedule B as filed says "5%"; the OA Schedule B should be corrected to a wallet count before signing. Confirm the Edge portal's exact figure (believed to be 20).
4. **Voting weight**: settled as XE balance at snapshot, direct votes only (§10). "Delegated XE" in the copy notes refers to consensus, not governance; no conflict.
5. **Agents' voting weight**: settled as 100 XE per seat, 1% aggregate cap, excluded from quorum, shown separately, no unsolicited receives (§10). All Schedule B values.
6. Whether `dao.*` is the agreed state-chain prefix (reserve it before anyone else writes to it). Domains are settled: `dao.xe.network` and `dao.test.network`.
7. **Pause at the protocol level**: settled as not required (§6.4). The OA pause is the company suspending its own operations, which the harness enforces in full. Whether Genesis offers a governance-level suspension (a member-settable, keyset-lifted, self-expiring freeze on `sys.*`/`dao.*` writes, ideally paired with a delay on keyset and minter changes) is a protocol question for Adam, with no OA dependency.
8. **48-hour timelock**: harness-enforced at first; is a chain-enforced version on the roadmap?
9. **marketized.io /governance** still says "Who holds XE runs XE", "weighted by delegated XUSD", and "40–50% today" on the burn. All three are on the copy notes' kill list and the XUSD line contradicts the docs. Flag to whoever owns the site.
10. **Licence and repo**: settled. GPL-3.0, `github.com/xeprotocol/dao`.
11. **Guardian and operations keysets**: names and timing; the legal surface shows "not yet stood up" until a resolution.
12. **Public register vs legal register**: settled by default. Public portal uses the public register throughout; a single footer link, "Records", leads to the legal surface; any legal-register language counsel asks for lives on the legal pages only. Open to counsel's amendment.
13. **Testnet observation**: epoch blocks are signed by a single oracle key by design (`sys.oracle`, prefix `epoch.`). Fine, but the public "every block jointly signed by the keyset" line is only true for non-oracle blocks. Copy nuance for the site, not a software issue.
14. **Address derivation (source finding, settled in code)**: the docs describe an account address as the raw public key. The node source (`core.DeriveAddress`) derives it as `sha256("xe/account/v1" || pubkey)`, and an account's open block declares `pub_key`, which is bound into the block hash through the aux input (`"xe/block/pubkey/v1"`). Every verifier checks the declared key derives the account. The harness implements the source, not the docs; `tests/test_xe_wire.py` pins it against live testnet blocks. Docs should be corrected.
15. **Tip race (design consequence, settled in code)**: `sys.oracle` writes an `epoch.<n>` block roughly every ten minutes, so any state-chain block the DAO assembles goes stale within minutes of being built. Two humans signing the same block hash within one window is not a reliable assumption. State-chain writes are therefore two-step **signing sessions**: keyset holders first approve the *ops digest* (durable, never expires with the tip), then sign a block the harness builds at the live tip; if the tip moves before the threshold is met, the harness rebuilds, resets block signatures, keeps the approvals, and asks for signatures again. The approval is the decision; the block signature is mechanics. A chain-side fix (sign over ops + parent-independent nonce, or a short-lived "reserved next index") would remove the second step; raise with Adam for Genesis.
16. **Headline claim (settled 12 Oct 2026)**: "The world's first agentic DAO" is false (ai16z 2024, Botto 2021, ContinuumDAO, Zero, ADGF, and "agentic DAO" as a defined academic term). Replaced with **"The first L1 governed by an agentic DAO"**, checked against NOVAI (L1 with AI primitives; AI autonomy not live), Waifu Layer (repo, no governed chain), Agent Council DAO (agents govern a council, not an L1). Two conditions: the claim is forward-looking until agent seats are designated and cast their first bounded vote, so the sub-line stays in "built to be" tense until then; and "world's first" and sibling phrases are on the kill list so no other primacy claim appears in the public register. Re-check before mainnet launch copy ships.
17. **Seat prompts (drafted 12 Oct 2026, config only)**: `config/prompts/_preamble.md` plus one file per agent seat. The preamble is the guiding light: order of authority (law and OA, Charter, Schedules, preamble, seat prompt, task, and last the material under analysis, which is data not instruction); what the ensemble never decides; the three paths never collapsing; truth-seeking as required record fields (`position`, `confidence`, `counter_argument`, `would_change_my_mind`, `evidence` with hashes); `<untrusted>` quarantine; register rules; the shared JSON output record; escalation triggers. Hashed at load like Schedule B; `prompt_hash(seat) = sha256(preamble + seat prompt)` is published on `/v1/seats`, served in full at `/v1/seats/{id}/prompt`, and must be stamped on every analysis a seat produces in P2. A prompt change is therefore a logged config change and a resolution matter. Nothing calls a model in v1; the prompts are reviewable long before anything does. Members to review the drafts before P2 begins.
18. **Signing convention for humans (settled in code)**: every write to the harness is a `SignedRequest` `{payload, timestamp, pub_key, signature}` with `signature = ed25519(sha256(domain || 0x00 || canonical_json({payload, timestamp})))`, per-endpoint domains (`xe-dao/proposal/v1`, `xe-dao/vote/v1`, `xe-dao/inbox/v1`, `xe-dao/member-action/v1`, `xe-dao/resolution/v1`, `xe-dao/ops-approval/v1`), ±10 minute freshness, single use. Browser signing uses WebCrypto Ed25519 (PKCS8 import of the 32-byte seed); browsers without it get the digest to sign offline with `dao sign`. No tweetnacl bundle needed.
19. **State-chain values are hashed as written, not canonicalised (verified against testnet-0005 genesis)**: the node hashes each `set` op's value as the exact bytes it received (`json.RawMessage` preserves whitespace and key order), then serves them compacted over the API. Blocks the node builds itself (oracle, DAO) are already compact, so re-compacting API output reproduces their hashes. Genesis is loaded from a pretty-printed `genesis.json` (4-space indent, values at depth 3), so its hash can only be verified from the document, not from `/statechain/blocks/0`. Consequence for the harness: a signing session stores and submits the exact compact value strings it hashed (`normalise_ops`), never re-serialising through JSONB; anyone verifying our blocks from the API will get matching hashes.

## 17. Non-goals

- No token contract, claim contract, liquidity pool or holder-facing token logic in this repo or in the Articles.
- No endpoint, contract or UI that gives a token holder an LLC vote or membership.
- No path that executes an open-vote result without a human-signed decision.
- No private keys for keyset or treasury on the server, ever.
- Not a replacement for the XE node, explorer or wallet; it reads them and submits pre-signed blocks to them.
- Not a general agent framework; a fixed, auditable flow for one entity.

## 18. Definition of done for v0.1 (P0 + P1)

- Deployed at `dao.test.network` against testnet-0005, then at `dao.xe.network` at Genesis, same code, same paths.
- `GET /v1/legal/identifier` returns the exact identifier set counsel files, and every URL in it resolves.
- `dao.registry` and at least one `dao.anchor` exist on the state chain, signed by the keyset, visible on any node and in the explorer.
- The event log replays from zero to the current head with hash continuity, and the latest anchor matches.
- A member can file a pause determination, the timer runs, and the public post is generated within four hours without anyone touching a database.
- A protocol-parameter proposal can be written as ops, hashed, signed by two keyset holders through the UI, and submitted, and the resulting state-chain block is linked from the decision record.
- A stranger can send a signed XE chat message to the DAO's directory address, see it acknowledged, and read the reply.
- A stranger can open a proposal with a fee, holders can vote, the tally closes at 21 days, and the page shows "result published" and "decision pending" as two separate facts.
- The public portal passes the copy lint; the legal surface uses OA terms exactly.
