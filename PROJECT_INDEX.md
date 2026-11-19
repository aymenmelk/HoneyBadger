# HoneyBadger project index

Reviewed commit: `7e56a5326346d0a7d2d7a07061e206fb413829b5` (branch `main`, 2026-11-10).
Index written 2026-11-19. Every path below was checked against that commit.

## What the project is

HoneyBadger is a self-contained honeypot. A fake SSH server (port 8022) and a fake
HTTP site (port 8081) accept attacker traffic. Each interaction becomes one event.
The event is enriched with GeoIP and a rule-based MITRE ATT&CK technique, stored in
PostgreSQL, streamed to a React dashboard over WebSocket, and exported as Prometheus
metrics for Grafana and Alertmanager. Everything runs from `docker-compose.yml`.
Passwords are stored only as `sha256:<hex>` hashes, and payload URLs are never fetched.

## Main entry points

| Purpose | Path |
|---|---|
| Stack definition and ports | `docker-compose.yml`, `.env.example` |
| Backend process entry point (wires buses, pipeline, listeners, API) | `backend/main.py` |
| Settings (`HB_*` environment variables) | `backend/config.py` |
| Event contract (`RawEvent`, `EnrichedEvent`, `EventOut`) | `backend/schemas.py` |
| SSH sensor and fake shell | `backend/sshd.py`, `backend/fakeshell.py` |
| HTTP sensor and bait pages | `backend/httpd.py`, `backend/http_routes.py` |
| In-process event bus | `backend/bus.py` |
| Enrichment pipeline | `backend/pipeline.py` |
| Enrichers | `backend/geoip.py`, `backend/mitre.py`, `backend/credentials.py`, `backend/payloads.py` |
| Persistence | `backend/storage.py`, `backend/db/models.py`, `backend/db/migrations/versions/001_initial_schema.py` |
| REST + WebSocket API (`/health`, `/events`, `/stats`, `/stats/timeseries`, `/ws/events`) | `backend/api.py` |
| Prometheus exporter and retention job | `backend/metrics.py`, `backend/retention.py` |
| Dashboard entry point and event types | `dashboard/src/app.tsx`, `dashboard/src/types.ts` |
| Dashboard data access | `dashboard/src/api/endpoints.ts`, `dashboard/src/ws/client.ts`, `dashboard/src/hooks/useLiveEvents.ts` |
| Monitoring config | `monitoring/prometheus/prometheus.yml`, `monitoring/prometheus/rules/alerts.yml`, `monitoring/grafana/dashboards/` |
| Tests | `backend/tests/`, `tests/attack_scenarios.py`, `tests/integration/`, `tests/security/`, `TESTING.md` |
| Design docs | `README.md`, `SYSTEM_ARCHITECTURE.md`, `REPO_STRUCTURE.md`, `docs/ARCHITECTURE.md` |

## Event flow: one SSH or HTTP observation

1. **Collection (SSH).** `SshHoneypotServer` in `backend/sshd.py` handles one TCP connection.
   It publishes up to three kinds of `RawEvent` with `service=ssh`:
   - `event_kind="ssh_handshake"`: client version string, published once per connection.
   - `event_kind="auth"`: from `validate_password()`. The username is kept, the password is
     hashed by `hash_password()`, and every login is accepted.
   - `event_kind="command"`: from `publish_command()` for each line typed in the fake shell
     (`backend/fakeshell.py`). `wget`/`curl` URLs are copied into `payload_url`.
   `RawEvent` rejects SSH events without a username and password hash, except handshakes.
2. **Collection (HTTP).** `HttpHoneypot` in `backend/httpd.py` catches every path. It serves a
   bait page from `select_bait()` in `backend/http_routes.py` or a 404. It extracts and hashes
   form credentials for `POST` to `/login`, `/wp-login.php`, `/phpmyadmin` and `/admin`. It then
   publishes a `RawEvent` with `service=http`, method, path, status, user agent and
   `additional_info={"event_kind": "http_request", "bait_hit": ..., "latency_ms": ...}`.
3. **Raw bus.** Both sensors call `EventBus.publish()` (`backend/bus.py`) on the raw bus created in
   `backend/main.py`. Publishing never blocks the sensor.
4. **Enrichment.** `EnrichmentPipeline._process_event()` in `backend/pipeline.py` runs, in order:
   GeoIP lookup (`backend/geoip.py`, cached in PostgreSQL), `classify()` from `backend/mitre.py`
   (returns `technique_id` and `severity`), credential counters (`backend/credentials.py`) and
   payload metadata (`backend/payloads.py`). It builds an `EnrichedEvent`.
5. **Storage.** `EventRepository.insert()` in `backend/storage.py` writes one row to the `events`
   table (`backend/db/models.py`). The timestamp column is named `ts`; the API exposes it as
   `timestamp`. Geo fields are flattened into columns, and `additional_info` is stored as JSON.
6. **Dashboard.** The pipeline publishes the `EnrichedEvent` to the enriched bus. The
   WebSocket broadcaster in `backend/api.py` sends `{"type": "event", "event": ...}` frames on
   `/ws/events`. The REST endpoints read PostgreSQL. The dashboard (`dashboard/src/app.tsx`)
   backfills with `GET /events`, merges live frames (`dashboard/src/lib/events.ts`) and polls
   `/stats`. `dashboard/src/types.ts::EventOut` mirrors `backend/schemas.py::EventOut`.
7. **Metrics.** `backend/metrics.py` serves Prometheus metrics on `:8000`; Prometheus evaluates
   `monitoring/prometheus/rules/alerts.yml`.

### Stored event fields (what an offline model could use)

`service`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `ts`, `username`,
`password_hash`, `user_agent`, `http_method`, `http_path`, `http_status_code`, `command`,
`payload_url`, `payload_hash`, `payload_size`, `technique_id`, `severity`, `country`, `region`,
`city`, `latitude`, `longitude`, `asn`, `additional_info`.
There is no per-event ground-truth label, byte count, session duration or session id.

## Where the offline analysis fits

The offline analysis lives at the repository root and is separate from the running stack.
It needs neither Docker nor the honeypot services nor the attack simulator.

| File | Role |
|---|---|
| `intrusion_analysis.ipynb` | Colab-ready notebook: data audit, grouped validation, baseline vs. random forest, predictions |
| `Train_data.csv` | Kaggle labeled connections (25,192 rows, `class` = `normal`/`anomaly`) |
| `Test_data.csv` | Kaggle unlabeled connections (22,544 rows, same 41 features, no `class`) |
| `intrusion_predictions.csv` | Notebook output: one prediction per `Test_data.csv` row, original order |

Dataset: <https://www.kaggle.com/datasets/sampadab17/network-intrusion-detection>
(publisher Sampada Bhosale; Kaggle lists the license as "Unknown").

| File | Bytes | SHA-256 |
|---|---|---|
| `Train_data.csv` | 2,875,560 | `1e40eb667611ab507870fc5b5ef0a844201ec094915d78d79f4665937e43b07a` |
| `Test_data.csv` | 2,416,180 | `a58db8c605e58411f6432dd9ab2fe10e1d768f058f5453e9e279788c7219caf8` |

The byte sizes match Kaggle's file listing. The checksums were computed locally; the notebook
re-checks them after every download.

A Kaggle row is one network connection summarised by 41 features (KDD-style). A HoneyBadger
row is one application-level event (a login, a command or an HTTP request). The data share
the `service` concept (`ssh`, `http`) but little else. Scores on the Kaggle data therefore do
not measure detection quality on live HoneyBadger events. The notebook's last section maps
the fields and lists the evidence needed for a real evaluation.

## Gaps noticed while indexing (not changed)

- `README.md` links `docs/API.md` and `docs/ROADMAP.md`, which do not exist.
  `docs/ANALYSIS.md`, `docs/RESPONSIBLE_DISCLOSURE.md` and `backend/alerts.py` are empty files.
- `backend/sim/simulate.py` is a stub (`run_scenario` only sleeps) and has no `--count` or
  `--delay` flags, although the README uses them. The working traffic driver is
  `tests/attack_scenarios.py`.
- `backend/pipeline.py` calls `record_payload_captured()` without importing it. The event is
  already stored and published at that point, so payload events are logged as pipeline
  errors and skip the latency metric.
- PostgreSQL is published on host port `15432` in `docker-compose.yml`, while the README
  table says `5432`.
