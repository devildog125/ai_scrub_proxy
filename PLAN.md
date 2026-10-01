# ai_scrub_proxy — Build Plan

**One line:** an Anthropic-API-compatible proxy, written in .NET, that strips CJI/PII from
everything Claude Code sends to Anthropic, with OpenAPPA sanitizing tool outputs before the
model sees them and an audit trail in the agency's SQL Server.

Status: plan only. Nothing built yet. Decisions recorded 2026-09-30, reframed 2026-10-01.

## 0. Threat model

**Who we are.** A development team inside a criminal-justice government shop. The users are
fellow developers using Claude Code: the CLI, the IDE extensions, and the Claude desktop
app's Code tab.

**The adversary is a well-meaning developer.** They paste a stack trace, a log line, a query
result, or a JSON fixture that contains CJI or PII into their context window. Or they ask
Claude to read a file or run a query, and the result contains it. Nobody is attacking the
system. The failure mode is an ordinary workday.

**What we protect against.** Raw identifiers (names, SSNs, driver's licence numbers, SIDs,
UCNs, DOBs next to names) and secrets (connection strings, API keys) reaching Anthropic's
API. Not: a developer who deliberately exfiltrates data by other means. That is an HR and
network-policy problem, not a proxy problem.

**Auth.** The design assumes **pass-through OAuth**: the proxy forwards each user's bearer token untouched, never
stores or logs it, and holds no Anthropic API key of its own. User identity for audit comes
from the first network hop (mTLS per workstation, or Windows Integrated auth on the proxy),
never from the OAuth token.

---

## 1. What we are building, and what we are not

Two different questions get conflated in "LLM data protection":

| Question | Who answers it |
|---|---|
| **What is this data?** Names, SSNs, SIDs, case numbers, plates, addresses. | **ai_scrub_proxy** (this repo) |
| **Where is this data allowed to go?** May a CJI-labeled tool result reach an external LLM? | **OpenAPPA** (archestra-ai/OpenAPPA, Rust, MIT) |

OpenAPPA is an information-flow policy engine. It labels every tool result with an *audience*
(`self ⊆ internal ⊆ public`, plus named groups like `@cji`) and a *trust* rank, and blocks a
tool call when restricted data would flow to a destination that is not permitted to see it.
When it blocks, it can offer a **sanitization remedy**: run the payload through a declared
sanitizer that is permitted to widen the audience (for example `@cji → public`).

**ai_scrub_proxy is one sanitizer applied at two layers.** The same detection core runs (1) in
the proxy, on the `messages` array of every API call, catching prompts and history, and
(2) behind OpenAPPA's `tool_result` hook with `replace_output`, cleaning Read, Bash, and MCP
outputs before the model sees them. The proxy is the backstop for anything the hook misses.
We do not reimplement policy or agent hooks; OpenAPPA does that and ships benchmarks for it.

Why this split is right for CJIS:

- The *decision* that data was restricted is deterministic and logged by OpenAPPA, not by a
  probabilistic classifier. Auditors like that.
- The *detection* (regex + local NER) is probabilistic. Keeping it in a single, testable,
  measurable component means we can report recall per entity type and improve it in isolation.
- Everything runs on-prem. OpenAPPA's engine makes no network or file calls; ai_scrub_proxy
  makes none either. Only the sanitized text reaches the LLM.

## 2. Confirmed facts about OpenAPPA (verified 2026-09-30)

- Language Rust, license MIT. Status "preview and RFC", wire surfaces may break without shims.
- Runs in-process (Rust/Python bindings, napi for TS) or as a sidecar: hooks `POST /hook`
  with `{"protocol": 1, "adapter": ..., "event": ...}` and get back a `decision`.
- Hook events: `session_start`, `prompt`, `tool_call`, `tool_result`, `turn_end`, plus
  child/spawn events. Decisions include `allow_call`, `deny_call`, `block`,
  `replace_output`, `deliver_value`, `refuse`, with optional `offers` (remedies).
- **Sanitizers are external HTTP services** declared in `appa.toml` with a `url` and a
  `permits` block, for example `audience = { from = ["internal"], to = ["public"] }`.
- Annotators (classify a tool call's output restrictions) can be local commands
  (`command = ["python3", "./classify_file.py"]`) or services.
- No .NET binding exists. None is needed: the sanitizer contract is plain HTTP, and the
  sidecar's hook contract is plain HTTP JSON that Claude Code's own OpenAPPA adapter speaks.

**Open item to verify before writing the endpoint:** the exact JSON body OpenAPPA POSTs to a
sanitizer `url` and the exact response it expects. Read `appa-policy/src` and
`appa-builtin` in the OpenAPPA repo, or run a stock sanitizer and capture the request.

## 3. Architecture

```
 Claude Code (CLI / IDE / desktop)          ANTHROPIC_BASE_URL = https://ai-scrub-proxy.agency.local
 ────────────────────────────────           ─────────────────────────────────────────────────
 tool runs (Read/Bash/MCP) ──tool_result──▶ OpenAPPA sidecar ──▶ ai_scrub_proxy /sanitize
                            ◀─replace_output─ sanitized tool output ◀──
 POST /v1/messages  ──────────────────────▶ ai_scrub_proxy (.NET)
   Authorization: Bearer <user OAuth>          identity from mTLS / Windows Integrated (hop 1)
                                               sanitize messages[] (regex + local NER)
                                               audit row → local durable queue → SQL Server
                                               forward, bearer untouched ──▶ api.anthropic.com
                            ◀────────────── response streamed back, plus a feedback note:
                                               "replaced 3 SSNs and 2 names"
 any other path  ─────────────────────────▶ forwarded unsanitized (OAuth, models, etc.)
```

Deployable pieces in this repo:

1. **`AiScrubProxy.Core`** (class library). Detect → pseudonymize with session-consistent
   surrogates. Zero network. Zero file I/O except reading the ONNX model at startup.
2. **`AiScrubProxy.Proxy`** (ASP.NET Core). Anthropic-API-compatible. Sanitizes
   `/v1/messages` request bodies, forwards everything else untouched, streams responses.
   Also serves OpenAPPA's sanitizer HTTP contract on `/sanitize` and `/healthz`.
3. **`AiScrubProxy.Audit`**. Durable local queue plus the SQL Server sink. See §5a.
4. **`AiScrubProxy.Cli`**. `sanitize`, `eval`, `verify`. For development and the recall gate.

## 3a. Deployment

ai_scrub_proxy is an API endpoint. From a developer's machine, nothing else changes.

**Supported clients, all pointed at the same proxy.** Listed in decreasing order of how
strongly "pointed at the proxy" can be enforced.

| Client | How it's pointed | How it's enforced |
|---|---|---|
| **a. CLI in a compose stack** | `claude-code` container with `ANTHROPIC_BASE_URL` set; sidecars: `ai_scrub_proxy`, `openappa`; external SQL Server | Container egress allowlist = proxy only. Strongest. |
| **b. CLI and IDE extensions on a workstation** | Same settings file and env var | Workstation network policy. |
| **c. Claude desktop app, Code tab** | Same engine and settings underneath, so hooks and `ANTHROPIC_BASE_URL` carry over | Managed settings that disable every side channel that bypasses the proxy: Artifact publishing, Remote Control, cloud sessions, and MCP connectors (Gmail, Drive, Calendar, Chrome, etc.). |

**Desktop app deliverables.** The managed-settings file is a tracked artefact in
`deploy/desktop/`, with a check that it survives app updates. If Phase 0 shows any side
channel cannot be disabled, the desktop app drops to **unsupported** and this section says why.

**Local state is in scope.** Transcripts under `~/.claude/projects` and the desktop app's
local data can contain CJI that was typed or read before sanitization. Every client needs
full-disk encryption and a retention/purge treatment for those paths. This repo documents
the requirement; the agency's endpoint management enforces it.

## 4. .NET stack and licenses

Presidio is Python-only, so the detection layer is rebuilt natively. All dependencies MIT
unless noted.

| Need | Choice | License | Notes |
|---|---|---|---|
| Runtime | .NET 10 LTS | MIT | |
| Structured identifiers | `System.Text.RegularExpressions` with `[GeneratedRegex]` | stdlib | SSN, phone, email, VIN, plate, FBI UCN, SID, case/docket formats |
| Names, locations, orgs | ONNX Runtime + a token-classification NER model | MIT (runtime); model license varies, check per model | Run fully local. Candidate: a DeBERTa/RoBERTa NER fine-tune exported to ONNX |
| Tokenizer | `Microsoft.ML.Tokenizers` | MIT | WordPiece/BPE for the chosen model |
| Secrets | gitleaks-style patterns ported to `[GeneratedRegex]` | stdlib (gitleaks rules are MIT) | Connection strings, API keys, bearer tokens, private key headers |
| HTTP | ASP.NET Core minimal API | MIT | |
| Reverse proxy | YARP (`Microsoft.ReverseProxy`) | MIT | Default route forwards non-Messages paths untouched; custom transform on `/v1/messages` |
| Surrogate map | In-memory `ConcurrentDictionary`, session-scoped, TTL | stdlib | Keeps `<PERSON_A>` stable within a session. No rehydration, so nothing sensitive persists |
| Audit queue | Local durable queue on SQLite (`Microsoft.Data.Sqlite`) | MIT | Delayed writes to SQL Server; see §5a |
| Audit store | External SQL Server via `Microsoft.Data.SqlClient` | MIT (client); SQL Server itself is commercially licensed | See §5a. Dev/test uses the Developer edition container |
| Audit tests | `Testcontainers.MsSql` | MIT | Spins up SQL Server in CI; no shared test database |

**Flag:** the NER model is the one dependency whose license must be checked at selection
time. Some strong NER checkpoints are CC-BY-NC or research-only. Pick an Apache/MIT one.

**Not using:** any cloud PII API (Azure AI Language PII, AWS Comprehend). They are
disqualified for CJI regardless of how good they are, because raw text would leave the enclave.

## 5a. Audit trail in an external SQL Server

Every sanitize operation, at either layer, writes an audit row to a SQL Server instance the
agency operates. This is the non-repudiation record CJIS asks for: who ran what, when, and
what was replaced. It never contains the plaintext it describes.

**What goes in a row, and what never does.**

| Stored | Never stored |
|---|---|
| UTC timestamp, service version, host name | Any entity value (name, SSN, plate, address) |
| Session ID and OpenAPPA call ID | The input text or output text |
| Caller identity from hop 1 (mTLS client cert or Windows Integrated principal) | Hashes of entity values. A hash of a name is a dictionary lookup away from the name |
| Layer: `proxy` or `tool_result_hook` | The user's OAuth bearer token, or any header |
| Event type: `sanitize`, `blocked`, `policy_denied`, `queue_flush` | Connection strings, keys |
| Per-entity-type counts (`PERSON: 3, SSN: 1`) and the surrogate IDs minted | |
| Outcome (`ok`, `rejected`, `error`) and a non-sensitive error code | |
| Hash of the previous row (tamper-evident chain) | |

**Design decisions.**

- **Append-only, enforced in the database, not in code.** The service's SQL login gets
  `INSERT` on the audit table and nothing else. No `UPDATE`, `DELETE`, or DDL. Schema
  changes are versioned SQL scripts in `db/migrations/` that a DBA applies, so the service
  cannot alter its own evidence.
- **Tamper evidence.** On SQL Server 2022+ or Azure SQL, use an **append-only ledger
  table**, which gives cryptographic verification for free. On older versions, the
  `PreviousRowHash` column chains rows so a deleted or edited row breaks verification.
  Build the chain either way; it's cheap and works everywhere.
- **Local durable queue, delayed writes.** The audit row is written synchronously to a
  local SQLite queue on the proxy host before the request is forwarded. A background
  writer drains the queue to SQL Server and deletes rows only after a confirmed insert.
  If SQL Server is down, developers keep working and the rows arrive late.
  **Trade-off, stated plainly:** an audit row can be delayed, and if the proxy host's disk
  is lost before the flush, it can be lost. The alternative, failing closed, blocks every
  developer in the shop whenever the database blinks, which was judged worse. The local
  queue file is itself CJIS-scope metadata: encrypt the disk, alert when queue depth or
  age exceeds a threshold, and treat a growing queue as an incident.
- **Connection and auth.** Connection string comes from the environment variable
  `AI_SCRUB_PROXY_AUDIT_CONNECTION`, documented in `.env.example`, never in code. Prefer
  Windows Integrated or Entra ID authentication over SQL logins. `Encrypt=Strict` and
  `TrustServerCertificate=false` are mandatory; the service refuses to start otherwise.
- **The audit database is in CJIS scope.** Even without plaintext, "who queried which
  session when" about criminal-justice work is sensitive metadata. The SQL Server needs
  encryption at rest (TDE), FIPS-validated TLS, access control, and its own audit. That is
  the agency's infrastructure, not this repo's, but the README must say it.
- **Retention.** The CJIS Security Policy sets a minimum retention period for audit records
  (one year at the time of writing; **verify against the current policy version** before
  stating it to a client). Retention and purge are DBA jobs, not service behaviour, so the
  service never has the permission to delete.
- **Auditing the audit.** A `verify` CLI command walks the chain (or calls the ledger
  verification procedure) and reports the first broken link. Run it on a schedule.

**Project:** `AiScrubProxy.Audit`, a small class library with one interface,
`IAuditSink`, the durable queue, two sinks (`SqlServerAuditSink`, `InMemoryAuditSink` for
tests), and a test that asserts no entity value or bearer token can appear in any column.

## 5. Phases

### Phase 0 — Spike (2 to 3 days)
Goal: prove the unknowns that can reshape the architecture before committing to it.

- [ ] **Does Claude Code's OAuth survive a custom base URL?** Stand up a dumb pass-through
      proxy. Verify login and token refresh round-trip through `ANTHROPIC_BASE_URL`, tested
      separately on the CLI and on the desktop app. **If this fails, the proxy must become
      a network-level intercept instead, and Phase 2 is a different build.** This is the
      one unknown that can reshape the plan.
- [ ] **Can managed settings disable the desktop app's side channels?** Artifact
      publishing, Remote Control, cloud sessions, MCP connectors. Test each. Any that cannot
      be disabled drops the desktop app to unsupported, and §3a records why.
- [ ] Confirm the proxy's default route forwards every non-Messages path unsanitized and
      nothing in Claude Code's startup breaks (model listing, OAuth endpoints, telemetry).
- [ ] Run OpenAPPA locally with its Claude Code playground. Trigger a `tool_result` hook
      with `replace_output`. Capture the sanitizer request/response JSON on the wire.
      **This resolves the open item in §2.**
- [ ] Load one candidate NER model in ONNX Runtime from .NET and tag a synthetic log file
      and JSON fixture. Measure latency per 1,000 tokens on the target hardware.

Exit criterion: a one-page note with the OAuth result, the desktop-app result, the
sanitizer contract, the chosen model, and its license.

### Phase 1 — Proxy, sanitize-only
Goal: every Claude Code client in the shop can point at it and keep working.

- [ ] `AiScrubProxy.Proxy` on YARP. Default route forwards everything untouched, bearer
      token included. `/v1/messages` gets a request transform that sanitizes every text
      block in `messages[]` and `system`. Streaming responses pass through unmodified.
- [ ] **No rehydration.** Surrogates stay in Claude's answer. See §9.
- [ ] **Feedback on every replacement.** The proxy appends a short note to the response so
      the developer sees it in their session: "ai_scrub_proxy replaced 3 SSNs and 2 names
      before sending." Mechanism decided in Phase 0 (likely a trailing text block).
- [ ] **Optional block mode** for high-confidence CJI (SID, UCN): refuse the request with
      an explanation instead of replacing. Off by default; per-deployment setting.
- [ ] Session-consistent surrogates: same value → same `<PERSON_A>` within a session, so
      Claude can still reason about "the same person" across turns.
- [ ] Identity from hop 1: mTLS client certificate or Windows Integrated. Reject
      unauthenticated callers. Never read identity from the OAuth token.
- [ ] Structured logs that **never** contain plaintext entities or any request header.
      Test asserts it.
- [ ] Bind to loopback or a Unix socket in the compose stack; enclave TLS elsewhere.

### Phase 2 — Recognizers tuned for developer artefacts
Goal: a recall number on the things developers actually paste.

- [ ] `AiScrubProxy.Core` recognizer interface, span merging, overlap resolution.
- [ ] Structured identifiers in **tabular output and log lines**: SSN, driver's licence,
      SID, UCN, DOB adjacent to a name, phone, email, VIN, plate.
- [ ] **Names in JSON fields** (`"lastName": "..."`, `"subject_name"`), CSV columns, and
      stack-trace message strings. Field-name context is a strong signal; use it.
- [ ] **Secrets**: gitleaks-style patterns for connection strings, API keys, bearer
      tokens, private-key headers. A pasted connection string is the most common leak.
- [ ] NER recognizer via ONNX Runtime for free-text names the structured rules miss.
- [ ] **Synthetic corpus** of developer artefacts with gold labels: logs, CSV exports,
      JSON fixtures, stack traces, SQL result grids. All values invented. No real CJI, ever.
- [ ] `eval` prints recall and precision per entity type. **Gate: recall ≥ 0.98 on
      structured identifiers and secrets, ≥ 0.95 on names, before Phase 3.**
- [ ] Unit tests (xUnit) for every recognizer. Every line commented per house style.

### Phase 3 — OpenAPPA tool_result hook
Goal: tool outputs are cleaned before the model sees them, not just before they leave.

- [ ] Serve OpenAPPA's sanitizer HTTP contract (captured in Phase 0) on `/sanitize`.
- [ ] `appa.toml`: Read, Bash, and MCP tool results labelled `@cji` by an annotator;
      ai_scrub_proxy declared as the sanitizer with
      `permits = { audience = { from = ["@cji"], to = ["public"] } }`; `tool_result` hook
      answers `replace_output` with the sanitized text.
- [ ] `appa replay` policy tests in `policy-tests/`: unsanitized → blocked; sanitized →
      allowed. Run in CI.
- [ ] Both layers write audit rows tagged with their layer, so a miss at the hook that the
      proxy caught is visible.

### Phase 4 — Audit sink to SQL Server
Goal: the record exists, is append-only, and survives a database outage. See §5a.

- [ ] `AiScrubProxy.Audit`: `IAuditSink`, local SQLite durable queue, background drain,
      SQL Server sink, in-memory sink, first migration script.
- [ ] Integration test with `Testcontainers.MsSql`: insert succeeds, update/delete are
      denied for the service login, chain verifies, queue drains after a simulated outage.
- [ ] Ledger table on SQL Server 2022+, `verify` CLI command, queue depth/age alerting,
      documented DBA retention job.

### Phase 5 — Client packaging
Goal: a developer or an admin can roll it out without reading this plan.

- [ ] `deploy/compose/`: `claude-code` container, `ai_scrub_proxy`, `openappa` sidecar,
      egress allowlist = proxy only, SQL Server connection via env var.
- [ ] `deploy/workstation/`: settings bundle (`settings.json`, hooks, `ANTHROPIC_BASE_URL`)
      for CLI and IDE extensions, plus the workstation network-policy requirement.
- [ ] `deploy/desktop/`: managed-settings file for the desktop app that disables Artifact
      publishing, Remote Control, cloud sessions, and MCP connectors. Include the check
      that it survives app updates.
- [ ] Local-state guidance: disk encryption and retention/purge for `~/.claude/projects`
      and desktop app data.

### CJIS hardening (runs alongside, not a phase)

- [ ] Indirect identifiers: configurable gazetteers for agency-specific field names,
      internal system IDs, and anything the recall gate shows leaking.
- [ ] Threat model document: what Anthropic's logs can contain (surrogates only), what the
      proxy host can contain (the audit queue; hence disk encryption), what a prompt-injected
      tool result can do (OpenAPPA's trust rank handles it).
- [ ] **Do not claim compliance.** That determination belongs to the agency's CJIS Systems
      Officer and their auditor.

## 6. Repo layout (target)

```
ai_scrub_proxy/
  PLAN.md                         this file
  AiScrubProxy.sln
  src/
    AiScrubProxy.Core/             detection, session-consistent surrogates
    AiScrubProxy.Proxy/            Anthropic-compatible proxy (YARP) + OpenAPPA /sanitize
    AiScrubProxy.Audit/            IAuditSink, durable queue, SQL Server sink, in-memory sink
    AiScrubProxy.Cli/              sanitize / eval / verify
  tests/
    AiScrubProxy.Core.Tests/       xUnit, one test class per recognizer
    AiScrubProxy.Proxy.Tests/      pass-through, streaming, feedback note, identity rejection
    corpus/                       synthetic dev artefacts + gold labels (JSONL)
  policy/
    appa.toml                     OpenAPPA policy: tool results @cji, ai_scrub_proxy as sanitizer
    policy-tests/                 appa replay fixtures
  deploy/
    compose/                      claude-code + ai_scrub_proxy + openappa, egress = proxy only
    workstation/                  settings bundle for CLI and IDE extensions
    desktop/                      managed-settings file + update-survival check
  db/
    migrations/                   versioned SQL scripts, applied by a DBA, never by the service
  .env.example                    AI_SCRUB_PROXY_AUDIT_CONNECTION and friends, dummy values
  models/                         .gitignored; download script + checksum, not the weights
```

## 7. Risks, stated plainly

- **OpenAPPA is pre-1.0.** The sanitizer contract may change under us. Mitigation: pin the
  OpenAPPA version in `policy/`, keep the contract adapter in one file.
- **The proxy only protects traffic that goes through it.** "Pointed at the proxy" is a
  configuration, not a guarantee. What makes it enforceable, in decreasing order of
  strength: the container egress allowlist, workstation network policy, desktop-app
  managed settings. A client outside all three is unprotected and the plan should say so
  rather than pretend otherwise.
- **OAuth through a custom base URL is unverified.** If login or refresh breaks, the proxy
  becomes a network intercept and Phase 1 changes shape. Phase 0 settles it first.
- **NER recall on developer artefacts is unproven.** Generic NER is trained on prose, not
  on JSON keys, log lines, and CSV grids. Field-name context and structured rules carry
  most of the load. Mitigation: the Phase 2 recall gate; fine-tune on synthetic data if it
  stays low.
- **A sanitizer that passes OpenAPPA's `permits` is trusted to be correct.** OpenAPPA will
  happily forward whatever we return as `public`. Our recall number *is* the security
  boundary. Treat the eval corpus as production code.
- **Delayed audit writes can be lost.** The local queue survives a database outage but not
  a lost proxy disk before the flush. Encrypt the disk, alert on queue depth and age, and
  treat a growing queue as an incident.
- **Compliance claims.** Nothing here makes a system CJIS-compliant. It makes one component
  of a system defensible. Say that in every README.

## 8. Decisions still open

1. Which NER model. Decided by the Phase 0 spike, constrained by license.
2. How the feedback note reaches the developer: trailing text block in the response, a
   response header the client ignores, or a hook-side message. Decided in Phase 0 once
   we see what each client renders.
3. Whether block mode ships on by default for SID and UCN, or stays opt-in.

## 9. Later, if ever

- **Rehydration.** Swapping surrogates back into Claude's answer. Developers don't need
  real names in Claude's output; they need working code. Rehydration is also where leaks
  happen: a real name goes back in and gets pasted somewhere. Not planned.
- **Streaming rehydration.** Follows from the above. Not planned.
- **.NET agent middleware** (`IChatClient` delegating handler). Dropped. Claude Code is
  the agent; the proxy covers it.
