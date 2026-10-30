# Deploying the XE DAO harness

Two deployments, one codebase: `dao.test.network` reads and writes testnet (`https://ldn.core.test.network`); `dao.xe.network` reads and writes mainnet once it exists. Everything below is for an Edge VPS running Docker Compose. Nothing is run on a laptop.

## 0. Prerequisites on the VPS

- Ubuntu 22.04/24.04, 2 vCPU, 4 GB, 40 GB disk.
- Docker Engine 24+ with the compose plugin: `curl -fsSL https://get.docker.com | sh`.
- DNS `A`/`AAAA` for `dao.test.network` (or `dao.xe.network`) pointing at the VPS.
- A reverse proxy for TLS. Caddy is simplest: `apt install caddy`, then `/etc/caddy/Caddyfile`:

  ```
  dao.test.network {
      reverse_proxy 127.0.0.1:8000
      encode gzip
      header {
          Strict-Transport-Security "max-age=31536000"
      }
  }
  ```

  `systemctl reload caddy`. Caddy provisions the certificate.

## 1. Get the code

```sh
sudo mkdir -p /opt/dao && sudo chown $USER /opt/dao
git clone https://github.com/xeprotocol/dao /opt/dao
cd /opt/dao
cp .env.example .env
```

Edit `.env`:

- `POSTGRES_PASSWORD`: long random, no `%` characters.
- `XE_NODE_URL`: `https://ldn.core.test.network` on testnet.
- `PUBLIC_BASE_URL`: `https://dao.test.network`.
- `DAO_SIGNER_PASSPHRASE`: long random; it encrypts the company keyfile.
- `GIT_COMMIT=$(git rev-parse --short HEAD)` (or let the deploy script below set it).

## 2. Build and run the tests first

```sh
cd /opt/dao
export GIT_COMMIT=$(git rev-parse --short HEAD)
docker compose build
```

Unit tests (no database, no network): byte-exact hashing against blocks captured from the live testnet, signed-request verification, keyfile, tally rules, copy lint, template parse.

```sh
docker compose run --rm --no-deps -v $PWD/tests:/app/tests app \
  sh -c "pip install -q pytest pytest-asyncio && pytest -q tests/test_xe_wire.py tests/test_dao_core.py tests/test_templates.py"
```

All of these must pass before the next step. If `test_block_hash_matches_testnet` or `test_statechain_genesis_and_oracle_hash` fail, stop: the protocol encoding has drifted and nothing the harness signs would be accepted.

Database-backed tests: the log chain, and the inbox / vote / fee hardening (uses a scratch database it wipes):

```sh
docker compose up -d db
docker compose exec db psql -U dao -d dao -c "CREATE DATABASE dao_test;"
docker compose run --rm -v $PWD/tests:/app/tests \
  -e DAO_TEST_DATABASE_URL="postgresql+asyncpg://dao:$(grep ^POSTGRES_PASSWORD .env | cut -d= -f2)@db:5432/dao_test" \
  app sh -c "pip install -q pytest pytest-asyncio && pytest -q tests/test_log_db.py tests/test_hardening_db.py"
```

## 3. Create the company keys

The keyfile holds the `harness` (signs the log), `dao` (chat, directory) and `fee` (receives/refunds/burns fees) keys, encrypted under `DAO_SIGNER_PASSPHRASE`. Create it once, on the VPS, into `./secrets` (mounted read-only into the containers):

```sh
mkdir -p secrets && chmod 700 secrets
docker compose run --rm --no-deps -v $PWD/secrets:/keys app dao keys init --path /keys/signer.json
```

The service's own `/app/secrets` mount is read-only and a `-v` on `run` does not replace it, hence the separate writable mount; the running services read the same file as `/app/secrets/signer.json`. Later `dao keys add|show` commands follow the same pattern with `--path /keys/signer.json`.

It prints three accounts. Put the `dao` and `fee` accounts into `config/schedule_c.yaml` under `accounts:` (the registry and the manifest read them from the signer anyway; the config copy is the public record). Back the keyfile up somewhere offline; `dao keys show` lists keys without revealing seeds.

## 4. Seat keys (people, on their own machines)

Each member and the CTO generates a personal key **on their own computer**, never on the server:

```sh
pip install pynacl  # once
python3 -c "import os,hashlib;from nacl.signing import SigningKey;s=os.urandom(32);k=SigningKey(s);p=bytes(k.verify_key);print('seed',s.hex());print('pub ',p.hex());print('acct',hashlib.sha256(b'xe/account/v1'+p).hexdigest())"
```

or, if the `dao` CLI is installed locally, `dao keys new-seat-key`. The seed stays with the person (password manager, hardware-backed store, paper). The **public key** goes into `config/schedule_c.yaml` → `human_seats[].public_key`. Restart `app` and `worker` after editing config.

Testnet keyset: `sys.dao_keyset` on testnet is currently 2-of-3 with keys that are not the founders' personal keys. For `dao.registry` and anchors to be writable on `dao.test.network`, either (a) the holders of two of those three keys load them in the members console to approve and sign sessions, or (b) a keyset rotation is written by the current holders to the founders' public keys. Until one of those happens, sessions will open and sit at "approving"; everything else works. Mainnet: the Genesis keyset is set to the members' keys at launch.

## 5. Start

```sh
cd /opt/dao
export GIT_COMMIT=$(git rev-parse --short HEAD)
docker compose up -d
docker compose logs -f --tail=100 app worker
```

Check:

```sh
curl -s https://dao.test.network/v1 | jq .
curl -s https://dao.test.network/v1/legal/identifier | jq .
curl -s https://dao.test.network/v1/health | jq .
curl -s https://dao.test.network/v1/log/verify
```

`GET /v1` must show `"network": "testnet"` and the `dao` and `fee` accounts. Within 20 minutes the worker registers the `dao` account in the node directory (`/v1/health` → `directory_registered: true`).

## 6. First actions in the members console

Open `https://dao.test.network/members`, load your seat key (it stays in the tab), and:

1. **Write `dao.registry`**: "Open registry session" → keyset holders "Approve ops" (durable) → when enough approvals land the harness builds a block at the live tip → keyset holders "Sign block hash" → the harness submits. If the oracle writes an epoch block in between, the block is rebuilt and signatures are collected again; approvals stand.
2. **First resolution**: propose an ordinary `note` resolution ("Harness v1 live on testnet"), both members sign. It lands in `/v1/legal/resolutions` and the log.
3. **Smoke the portal**: from any XE wallet send 10 XE to the fee account, submit a proposal with the send hash at `/proposals/new`, vote from a second wallet, check `/v1/proposals/<hash>`. The window is 21 days; to test close-out on testnet, temporarily set `windows.open_vote_days: 0` in `config/schedule_b.yaml`, restart `worker`, open a proposal, wait a minute, restore the value.
4. **Chat**: from any XE account send a chat envelope to the `dao` account; the worker logs it (`inbox.received`), acknowledges it, and your reply from the console goes out as `outbox.sent`.

## 7. Operating

- **Upgrade**: `git pull && export GIT_COMMIT=$(git rev-parse --short HEAD) && docker compose build && docker compose up -d`. Migrations run in the `migrate` service before `app`/`worker` start.
- **Config change**: edit under `config/`, restart `app worker`. The new hashes appear in `api.started`/`worker.started` log events and `/v1/legal/identifier`. A Schedule B/C change is itself a resolution matter; pass it first, change the file second.
- **Backups**: `docker compose exec db pg_dump -U dao dao | gzip > /opt/backups/dao-$(date +%F).sql.gz` nightly via cron; copy `secrets/signer.json` offline once (it does not change unless you add keys).
- **Verify the log** at any time: `curl -s https://dao.test.network/v1/log/verify` or `docker compose exec app dao verify-log`.
- **Copy lint**: `docker compose exec app dao copy-lint` must print `clean` before any public copy change ships.
- **Pause**: members only, from the console. While paused the worker stops outbound chat, fee movements and new anchors; reads, the log and vote intake stay up.

## 8. Mainnet (`dao.xe.network`)

Same steps with `XE_NODE_URL` set to a mainnet node and `PUBLIC_BASE_URL=https://dao.xe.network`. Create a fresh keyfile; never reuse testnet company keys. Check `GET /v1` reports `"network": "mainnet"` before publishing the URL anywhere.
