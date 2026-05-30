# CASB — Cloud Access Security Broker

A lightweight, self-hosted security proxy that inspects outbound HTTP traffic in real time, detects sensitive data before it leaves your network, and enforces configurable policies to block or flag violations.

Built as an open-source alternative to enterprise CASB solutions (Netskope, Zscaler) — deployable by a single engineer, no cloud dependency, no per-seat licensing.

---

## The Problem

Employees can upload sensitive files — source code, credentials, PII — to external services like Google Drive with no inspection layer in between. Most small organizations have no visibility into what's leaving their network, and enterprise CASB tools cost tens of thousands of dollars per year.

---

## How It Works

```
User uploads file to Google Drive
        │
        ▼
  mitmproxy intercepts (port 8080)
        │
        ▼
  POST /inspect → FastAPI
        │
        ▼
  3-stage classification pipeline:
  1. Regex    → AWS keys, emails, SSNs, credit cards
  2. YARA     → source code, config files, key material
  3. Ollama   → ambiguous content (local AI, no data leaves)
        │
        ▼
  Bypass detector → checks if file is disguised
  (e.g. secrets.py renamed to notes.txt)
        │
        ▼
  Policy engine → BLOCK / DRY_RUN / ALLOW
        │
        ▼
  Event logged to SQLite
        │
        ├── BLOCK   → 403 returned to user
        └── ALLOW   → request passes through
```

---

## Features

- **Real-time interception** of outbound POST/PUT requests via mitmproxy
- **3-stage classifier**: regex → YARA → local AI (Ollama), each stage only runs if the previous is not confident enough
- **Bypass detection**: catches files renamed to hide their true type (`.py` → `.txt`)
- **Policy engine**: YAML-defined rules with `BLOCK`, `ALLOW`, and `DRY_RUN` modes
- **Live dashboard**: events table, violation charts, policy viewer, rule browser
- **Zero data exfiltration**: AI classification runs locally via Ollama — content never sent to a third party

---

## Tech Stack

| Layer | Technology |
|---|---|
| Traffic interception | mitmproxy |
| Language | Python 3.12 |
| File type detection | python-magic |
| Pattern matching | yara-python + regex |
| AI classification | Ollama (llama3.2, local) |
| Policy engine | YAML + Python evaluator |
| Storage | SQLite + SQLModel |
| API | FastAPI |
| Dashboard | HTMX + Tailwind CSS + Chart.js |
| Testing | pytest + corpus-based regression suite |
| Package management | uv |

---

## Project Structure

```
casb/
├── proxy/
│   └── addon.py              # mitmproxy addon — intercepts uploads
├── inspector/
│   ├── pipeline.py           # orchestrates the 3 classifier stages
│   ├── regex_classifier.py
│   ├── yara_classifier.py
│   ├── ollama_classifier.py
│   ├── bypass_detector.py
│   └── regex_rules.yaml      # regex patterns per category
├── policy/
│   ├── engine.py             # reads policies.yaml, returns action
│   └── policies.yaml         # your enforcement rules
├── api/
│   ├── main.py               # FastAPI app + lifespan
│   ├── models.py             # SQLModel Event table
│   └── routes.py             # /inspect, /api/events, /api/stats, etc.
├── dashboard/
│   └── templates/
│       └── index.html        # single-page dashboard
├── rules/
│   └── source_code.yar       # YARA rules
├── tests/
│   ├── corpus/
│   │   ├── should_block/     # files that must be caught
│   │   └── should_allow/     # files that must pass through
│   ├── test_regex_classifier.py
│   ├── test_yara_classifier.py
│   ├── test_ollama_classifier.py
│   ├── test_pipeline.py
│   ├── test_bypass_detector.py
│   └── test_policy_engine.py
├── Procfile                  # honcho process definitions
├── pyproject.toml
└── README.md
```

---

## Setup

### Prerequisites

- Python 3.12
- [uv](https://astral.sh/uv)
- [Ollama](https://ollama.com) with `llama3.2` pulled
- libmagic (for python-magic)

**Install libmagic:**

```bash
# macOS
brew install libmagic

# Ubuntu / Debian
sudo apt install libmagic1

# Windows — install python-magic-bin instead
uv add python-magic-bin
```

**Pull the Ollama model:**

```bash
ollama pull llama3.2
```

### Install dependencies

```bash
git clone https://github.com/yourname/casb.git
cd casb
uv sync
```

### Install the mitmproxy certificate

Start mitmproxy once, then visit `http://mitm.it` with your proxy set to `localhost:8080` and install the certificate for your OS. This is a one-time step required for HTTPS inspection.

---

## Running

Start all three services with one command:

```bash
uv run honcho start
```

This starts:
- **FastAPI** inspector at `http://localhost:8000`
- **mitmproxy** at `http://localhost:8080`
- **Mock server** for local testing

Then open the dashboard:

```
http://localhost:8000
```

---

## Configuration

### Adding a policy

Edit `policy/policies.yaml`:

```yaml
policies:
  - name: block_source_code_gdrive
    category: source_code
    destination: "*.googleapis.com"
    min_confidence: 0.75
    action: BLOCK
    mode: enforce

  - name: dry_run_pii
    category: pii
    destination: "*"
    min_confidence: 0.70
    action: DRY_RUN
    mode: dry_run
```

Restart the server for policy changes to take effect.

### Adding a watched destination

Edit `proxy/addon.py`:

```python
WATCHED_DESTINATIONS = [
    "googleapis.com",
    "dropbox.com",
    "api.dropboxapi.com",
    "slack.com",       # add new destinations here
]
```

### Adding a regex rule

Edit `inspector/regex_rules.yaml`:

```yaml
rules:
  - name: my_custom_pattern
    category: credentials
    pattern: "MY_SECRET_[A-Z0-9]{20}"
    confidence: 0.90
```

---

## Testing

Run the full test suite:

```bash
uv run pytest tests/ -v
```

The corpus-based tests in `tests/corpus/` act as a regression suite — every file in `should_block/` must be caught, every file in `should_allow/` must pass. Add new files there as you discover edge cases.

---

## Demo Scenario

With everything running and proxy set to `localhost:8080`:

**1. Upload source code — blocked:**
```bash
curl -x http://localhost:8080 \
  -X POST https://www.googleapis.com/upload/drive/v3/files \
  -H "X-File-Name: main.py" \
  --data "import os
def get_secret():
    return os.environ['API_KEY']
class Config:
    pass" \
  --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem
```
Expected: `403 CASB BLOCKED: Policy violation: source_code`

**2. Same content, renamed to bypass detection:**
```bash
curl -x http://localhost:8080 \
  -X POST https://www.googleapis.com/upload/drive/v3/files \
  -H "X-File-Name: notes.txt" \
  --data "import os
def get_secret():
    return os.environ['API_KEY']" \
  --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem
```
Expected: `403 CASB BLOCKED: ... [BYPASS ATTEMPT DETECTED]`

**3. Clean file — allowed through:**
```bash
curl -x http://localhost:8080 \
  -X POST https://www.googleapis.com/upload/drive/v3/files \
  -H "X-File-Name: readme.txt" \
  --data "This is a normal readme with nothing sensitive." \
  --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem
```
Expected: request passes through normally

Both blocked events appear in the dashboard at `http://localhost:8000` under the Events view.

---

## Limitations (v1)

- HTTP/HTTPS inspection only — does not inspect traffic from native desktop sync clients (Google Drive for Desktop, Dropbox app)
- Single-node only — SQLite storage, no clustering
- Ollama classification adds 1–3 seconds latency for ambiguous content
- Certificate must be manually installed per device

---

## Roadmap

- [ ] Docker Compose packaging
- [ ] PostgreSQL migration for multi-node deployments
- [ ] Alert webhooks (Slack, email) on high-severity violations
- [ ] Per-user policy exceptions
- [ ] CI/CD pipeline with GitHub Actions corpus regression
- [ ] Policy DSL parser (replace YAML with `BLOCK IF category=source_code AND destination=gdrive`)

---

## License

MIT