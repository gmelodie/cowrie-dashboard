# honey

SSH/Telnet honeypot that captures attacker sessions and serves them in a live web dashboard with downloadable credential wordlists.

**Stack:** Cowrie → PostgreSQL → Flask → Nginx (SSL + reCAPTCHA)

Cowrie listens on 2222/2223 (redirected from 22/23 via iptables). Sessions, logins, commands, and downloads go to PostgreSQL. Stats and wordlists are precomputed by background workers and served instantly by the web server.

---

## Prerequisites

- Linux VPS with a public IP and a domain pointed at it
- Docker and Docker Compose v2
- Root / sudo access

---

## Setup

### 1. Clone

```bash
git clone <repo-url> ~/honey
cd ~/honey
```

### 2. Move your real SSH off port 22

Do this **before** touching iptables or you will lock yourself out.

```bash
echo "Port 22222" | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart sshd
```

Open a new terminal and confirm login on the new port before continuing.

### 3. Configure .env

```bash
cp env.example .env
nano .env
```

`env.example` is grouped by concern (Postgres, reCAPTCHA, federation, admin auth, etc.) with inline comments. At minimum set a strong `POSTGRES_PASSWORD`, your `TARGET_HOST`, and reCAPTCHA keys.

Get reCAPTCHA keys at [google.com/recaptcha/admin](https://www.google.com/recaptcha/admin) — add your domain, choose v2 Checkbox, paste both keys. Leave blank to disable the gate.

### 4. Start the stack

```bash
docker compose up -d
```

| Service | Role |
|---|---|
| `postgres` | Stores all honeypot data |
| `postgres-init` | Applies DB schema (runs once, exits) |
| `cowrie` | SSH/Telnet honeypot on 2222/2223 |
| `honey-jobs-stats` | Precomputes dashboard stats every 5 minutes |
| `honey-jobs-wordlist` | Generates credential wordlists every 6 hours |
| `honey-federation` | Federation HTTP daemon (peering, wordlist exchange) |
| `bloom-init` | One-shot: builds the reference Bloom filter |
| `geoip-init` | One-shot: downloads GeoIP MMDBs |
| `web` | Dashboard on localhost:8373 (admin panel at /admin/) |
| `nginx` | Routes 80/443 by domain |
| `certbot` | Renews SSL every 12 hours |

The honey binary is built from `./honey/` and reused across services with different `command:` args. The same image runs the daemon, the scheduled jobs, and any one-shot CLI invocation.

### 5. Obtain SSL certificate

```bash
TARGET_HOST=honey.example.com CERTBOT_EMAIL=you@example.com \
  docker compose run --rm honey-federation ops letsencrypt
docker compose restart nginx
```

### 6. Redirect ports 22 and 23 to Cowrie

```bash
sudo docker compose run --rm --privileged --network host honey-federation ops port-redirect
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

### 7. Verify

```bash
ssh root@your-server-ip    # should land in a fake shell
```

Open `https://honey.example.com`.

---

## Importing existing Cowrie logs

If you have existing Cowrie JSON logs, import them into the database:

```bash
docker compose run --rm \
  -v /path/to/logs:/logs:ro \
  honey-federation import cowrie-json /logs/cowrie.json
```

- Reads DB credentials from `.env` automatically
- Safe to re-run on overlapping files — duplicates are skipped via `ON CONFLICT DO NOTHING`
- After import, the scheduled jobs will pick up the new data on their next run

## Federation

Two honeypots can mutually peer to share wordlist observations and aggregate stats (top usernames/passwords, country breakdowns, command frequencies).

- **Admin panel:** `https://<host>/admin/` — basic-auth gated, shows pending requests, peers, and federated entries.
- **CLI:** `docker compose exec honey-federation honey federation peers …` (request, list, pending, approve, reject, revoke).
- **Trust root:** out-of-band fingerprint verification. Always compare the 52-char `base32` fingerprint between admins before approving any pending request.
- **Wire protocol:** signed Ed25519 envelopes with canonical JSON; signatures verified before any DB write; bad sigs from known peers drop the peer's local score.

### Federation backup

Two things to back up if you intend to keep a federated identity stable across redeploys:

```bash
# Node private key — re-creating this means re-peering with everyone.
docker run --rm -v honey-data:/data alpine cat /data/node.key > node.key.bak

# Federation tables (peers, pending requests, federated entries, nonces)
pg_dump --table='federation_*' --table='federated_*' \
        -U "$POSTGRES_USER" -h 127.0.0.1 -d "$POSTGRES_DB" > federation.sql
```

To restore on a new host, copy `node.key.bak` into the `honey-data` volume at `/data/honey/node.key` (mode `0600`), then `psql -f federation.sql`.

---

## Configuration reference

All env vars live in `.env`; the relevant ones are:

| Var | Default | Purpose |
|---|---|---|
| `POSTGRES_*` | — | DB connection (used by every container) |
| `HONEY_DATA_DIR` | `/data/honey` | Where the node identity key is kept |
| `HONEY_NODE_NAME` | — | Display name advertised to peers |
| `HONEY_CONTACT` | — | Display contact advertised to peers |
| `HONEY_FEDERATION_BIND` | `127.0.0.1:8088` | Daemon listen address (nginx proxies to it) |
| `HONEY_PUBLIC_URL` | `http://127.0.0.1:8088` | URL we advertise in outgoing peer requests |
| `HONEY_DAEMON_INTERNAL_URL` | `http://127.0.0.1:8088` | Loopback URL the CLI + admin panel use |
| `HONEY_POLL_INTERVAL_SECS` | `10` | How often the poller pulls from each trusted peer |
| `HONEY_MAX_SKEW_SECS` | `300` | Max accepted clock skew for signed envelopes |
| `HONEY_ADMIN_USER` | — | nginx basic-auth username for `/admin/` |
| `HONEY_ADMIN_PASSWORD_HASH` | — | htpasswd-format hash (use `openssl passwd -apr1`) |
| `VIRUSTOTAL_API_KEY` | — | Optional; enriches downloaded-malware analysis (MalwareBazaar is always queried) |
| `CERTBOT_EMAIL` | — | Used by `honey ops letsencrypt` for cert issuance |
| `RUST_LOG` | `info` | tracing-subscriber filter, e.g. `honey_server=debug` |

---

## Notes

- All containers use `network_mode: host` and communicate via `127.0.0.1`.
- `.env` is gitignored — never commit it.
- Dashboard stats refresh every 5 minutes; wordlists every 6 hours.
- `honey ops port-redirect` is idempotent — safe to re-run.
