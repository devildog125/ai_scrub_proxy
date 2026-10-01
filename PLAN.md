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
- The *detection* is deterministic too: a registry of rules, no learned model. Every
  replacement traces to a rule ID, so an auditor can ask "why was this scrubbed?" and get
  an answer. Same input, same output, every run. Recall and precision are measured per rule.
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
                                               detect: rule registry, in-process, no ML
                                               pseudonymize: session-stable surrogates
                                               audit row → local durable queue → SQL Server
                                               forward, bearer untouched ──▶ api.anthropic.com
                            ◀────────────── response streamed back, plus a feedback note:
                                               "replaced 3 SSNs and 2 names"
 any other path  ─────────────────────────▶ forwarded unsanitized (OAuth, models, etc.)
```

Deployable pieces in this repo:

1. **`AiScrubProxy.Core`** (class library). The rule registry loader, the two-stage
   scanner, span merging, and pseudonymization with session-consistent surrogates.
   Zero network. Zero file I/O except loading the registry at startup. See §4a.
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
| **a. CLI in a compose stack** | `claude-code` container with `ANTHROPIC_BASE_URL` set; sidecars: `ai_scrub_proxy` (.NET), `openappa`; external SQL Server | Container egress allowlist = proxy only. Strongest. |
| **b. CLI and IDE extensions on a workstation** | Same settings file and env var | Workstation network policy. |
| **c. Claude desktop app, Code tab** | Same engine and settings underneath, so hooks and `ANTHROPIC_BASE_URL` carry over | Managed settings that pin `ANTHROPIC_BASE_URL` in the `env` block, define the OpenAPPA hooks so developers can't remove them, and disable Artifact publishing. |

**Desktop app: what managed settings do and don't lock down (v1 decisions).**

- **Locked:** `ANTHROPIC_BASE_URL`, the OpenAPPA hook definitions, Artifact publishing off.
- **Allowed without restriction:** MCP connectors (Gmail, Drive, Calendar, Chrome, etc.).
  OpenAPPA covers data coming *in* from them via the `tool_result` hook, and the
  default-public policy rule in Phase 3 blocks outbound connector calls once a session is
  tainted. See §7 for the gap this leaves.
- **Left as shipped:** web search, web fetch, built-in browser, computer use, cloud
  sessions, Remote Control, bypass-permissions mode. Recorded as a decision in §7.

The managed-settings file is a tracked deliverable in `deploy/desktop/`, with a check that
it survives app updates. If Phase 0 shows Artifact publishing can't be disabled, that is
recorded as a gap in §7; the desktop app stays supported.

**Local state is in scope.** Transcripts under `~/.claude/projects` and the desktop app's
local data can contain CJI that was typed or read before sanitization. Every client needs
full-disk encryption and a retention/purge treatment for those paths. This repo documents
the requirement; the agency's endpoint management enforces it.

## 4. .NET stack and licenses

Detection is native .NET and rule-based. No Python, no Presidio, no NER or any other
learned model. All dependencies MIT unless noted.

| Need | Choice | License | Notes |
|---|---|---|---|
| Runtime | .NET 10 LTS | MIT | |
| Rule registry | YAML files under `recognizers/`, loaded at startup | n/a | One entry per type: id, category, shape, pattern, context words, validator, source. See §4a |
| Pattern matching | `System.Text.RegularExpressions`, compiled and cached; `[GeneratedRegex]` for the hot-path shape classifier | stdlib | Thousands of patterns are fine because the shape prefilter means only a handful run per token |
| Field-name dictionary | YAML under `recognizers/fields/`, generated from NIEM, NIBRS, and the agency's own schemas | n/a | Column names and JSON keys → category. Highest-precision signal in developer artefacts |
| Name lists | Public-domain surname and given-name lists (US Census) as gazetteers | public domain | Free-text name detection without a model. Only fires with context (see §4a) |
| Validators | Check-digit and format validators in C# (`IValidator`) | stdlib | VIN check digit, SSN area rules, date plausibility. Cut false positives |
| Secrets | gitleaks-style patterns ported into the registry | gitleaks rules are MIT | Connection strings, API keys, bearer tokens, private key headers |
| Registry import tool | `tools/ImportTaxonomy`, a .NET console app | stdlib + YAML lib (MIT) | Reads NIEM XSD and NIBRS element lists, emits taxonomy and field-name YAML |
| HTTP | ASP.NET Core minimal API | MIT | |
| Reverse proxy | YARP (`Microsoft.ReverseProxy`) | MIT | Default route forwards non-Messages paths untouched; custom transform on `/v1/messages` |
| Surrogate map | In-memory `ConcurrentDictionary`, session-scoped, TTL | stdlib | Keeps `<PERSON_A>` stable within a session. No rehydration, so nothing sensitive persists |
| Audit queue | Local durable queue on SQLite (`Microsoft.Data.Sqlite`) | MIT | Delayed writes to SQL Server; see §5a |
| Audit store | External SQL Server via `Microsoft.Data.SqlClient` | MIT (client); SQL Server itself is commercially licensed | See §5a. Dev/test uses the Developer edition container |
| Audit tests | `Testcontainers.MsSql` | MIT | Spins up SQL Server in CI; no shared test database |

**Not using:** any cloud PII API (Azure AI Language PII, AWS Comprehend), because raw text
would leave the enclave. Any NER or other learned model, because a replacement that can't
be explained by a rule can't be audited, and a model's behaviour can shift with a retrain.
Presidio, because it is Python and its NER path is a model.

## 4a. Detection design: a deterministic rule registry

The requirement is thousands of CJI and PII types, every one explainable. That rules out
hand-written code per type and rules out models. The design is a data-driven registry with
a prefilter so cost stays flat as the registry grows.

**One registry entry per type.** YAML, one file per source family, loaded at startup:

```yaml
- id: MO_DL_NUMBER            # stable, referenced by audit rows
  category: DRIVERS_LICENSE   # what Claude sees: <DL_A>
  source: "Agency DMV data dictionary v3"   # where the rule came from
  shape: "A999999999"         # prefilter key, see below
  pattern: "^[A-Z][0-9]{9}$"
  context: ["DL", "DLN", "license", "licence", "OLN"]   # words nearby that raise confidence
  validator: none             # or a named C# IValidator, e.g. VinCheckDigit
  confidence: 0.8             # with context → 1.0; below threshold → not replaced
  examples: ["A123456789"]    # feeds the synthetic corpus and the per-rule test
```

**Two-stage scan, so thousands of rules don't mean thousands of regex passes.**

1. **Shape classification.** One compiled pass tokenises the text and labels each token
   by shape: letter runs, digit runs, separators. `A123456789` becomes `A999999999`.
   `555-12-3456` becomes `999-99-9999`.
2. **Rule dispatch.** Each shape maps to the short list of rules that could match it.
   Only those run their pattern, context check, and validator. A driver's licence rule is
   never evaluated against something shaped like an email address.

**Field names are the strongest signal and the cheapest.** In JSON, CSV, log lines, and
SQL grids, the key or column header tells you what the value is. A dictionary mapping
`ssn`, `social_security_number`, `SubjectSSN`, `PersonSSNIdentification` and thousands of
others to a category catches values regardless of their shape. Generated from NIEM and
NIBRS element names plus the agency's own schema exports. Never committed with real data.

**Free-text names without a model.** Capitalised tokens that appear in a public-domain
surname or given-name list, *and* sit next to a context word (`name`, `subject`, `victim`,
`arrestee`, `DOB`, a title, or a DL/SSN match on the same line). A name list alone would
flag every `Smith` in a code comment. Context is what keeps precision up. Recall on prose
will be lower than a model would give; developer artefacts are mostly structured, which is
why this is acceptable here and the eval corpus has to prove it.

**Categories, not types, for everything downstream.** Claude sees `<DL_A>`, never
`<MO_DL_NUMBER_A>`. Surrogates are stable per category within a session. The audit row
stores both the category and the rule ID that fired, so the record is precise without the
placeholder vocabulary becoming unreadable.

**Every rule carries its own test.** The `examples` field drives the synthetic corpus and
a per-rule unit test. Adding a type with no examples fails CI. Adding a type that
collides with an existing rule's negative examples fails CI.

**Sources of truth for the registry, in priority order.**

| Source | Public? | What it gives |
|---|---|---|
| NIEM (OASIS NIEMOpen), Core and Justice domains | Yes | Thousands of element names → field-name dictionary and category taxonomy; republished NCIC code lists in its `ncic` namespace |
| FBI NIBRS technical specification | Yes | Offender, victim, arrestee, property data elements |
| FBI EBTS | Yes | FBI number (UCN), SID, and biometric record field formats |
| AAMVA DL/ID card design standard | Yes | Document-level licence formats |
| US Census surname and given-name files | Yes, public domain | Name gazetteers |
| gitleaks rules | Yes, MIT | Secret patterns |
| Agency DMV, court, and RMS data dictionaries | **No** | Per-state formats and local field names. Supplied by the agency, imported by tool, the import output reviewed before commit, raw files never committed |
| NCIC Code Manual and Operating Manual | **No**, CJIS-restricted | Only via the agency channel. Rules may reference code-list IDs; the lists themselves stay out of the repo |

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
- [ ] Confirm the proxy's default route forwards every non-Messages path unsanitized and
      nothing in Claude Code's startup breaks (model listing, OAuth endpoints, telemetry).
- [ ] **Can managed settings disable Artifact publishing on the desktop app?** If not,
      record it as a gap in §7. The desktop app stays supported either way.
- [ ] **Registry scale spike.** Build the shape classifier and rule dispatch with 2,000
      synthetic rules. Measure latency per 10 KB of mixed log/JSON text on the target
      hardware. The number has to be low enough that developers don't notice it.
- [ ] Pull the NIEM release and the NIBRS element list. Run a first pass of the import tool
      and count how many field names and categories fall out. This sizes Phase 2.
- [ ] Run OpenAPPA's Claude Code playground. Trigger a block and a sanitize offer. Capture
      the sanitizer request/response JSON on the wire. **This resolves the open item in §2.**

Exit criterion: a one-page note with the OAuth result, the Artifact-publishing result, the
registry latency number, the NIEM/NIBRS import count, and the sanitizer contract.

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

### Phase 2 — The rule registry, tuned for developer artefacts
Goal: recall and precision numbers on the things developers actually paste, with every
replacement traceable to a rule ID. See §4a for the design.

- [ ] `AiScrubProxy.Core`: registry loader, shape classifier, rule dispatch, span merging,
      overlap resolution, `IValidator` with VIN check digit and SSN area rules.
- [ ] `tools/ImportTaxonomy`: reads NIEM XSD and the NIBRS element list, emits the
      category taxonomy and field-name dictionary. Output is reviewed and committed; the
      tool is re-runnable when a new NIEM release lands.
- [ ] Hand-authored rules for the structured identifiers that need a pattern: SSN, driver's
      licence (per state, from agency dictionaries), SID, UCN, docket, DOB adjacent to a
      name, phone, email, VIN, plate.
- [ ] **Field-name dictionary** covering JSON keys (`"lastName"`, `"subject_name"`), CSV
      headers, SQL column names, and log-line labels. Values under a known field are
      replaced regardless of shape.
- [ ] **Name gazetteers with context rules**, per §4a. Measure precision on code
      comments and identifiers specifically; this is where it will hurt.
- [ ] **Secrets**: gitleaks-style patterns for connection strings, API keys, bearer
      tokens, private-key headers. A pasted connection string is the most common leak.
- [ ] **Synthetic corpus** of developer artefacts with gold labels: logs, CSV exports,
      JSON fixtures, stack traces, SQL result grids. All values invented. No real CJI, ever.
      Include **negative examples**: code identifiers, GUIDs, version numbers, commit hashes,
      and variable names that look like PII but aren't.
- [ ] `eval` prints recall **and precision** per category and per rule. **Gate: recall
      ≥ 0.98 on structured identifiers and secrets, ≥ 0.95 on names in structured fields,
      before Phase 3.** Free-text names get a reported number, not a gate, in v1.
      Precision on code identifiers is reported alongside; false positives are the
      complaint generator and the reason developers route around the proxy.
- [ ] Per-rule tests generated from each registry entry's `examples`. A rule with no
      examples fails CI. Unit tests (xUnit) for the scanner itself. Every line commented
      per house style.

### Phase 3 — OpenAPPA tool_result hook
Goal: tool outputs are cleaned before the model sees them, not just before they leave.

- [ ] Serve OpenAPPA's sanitizer HTTP contract (captured in Phase 0) on `/sanitize`.
- [ ] `appa.toml`: Read, Bash, and MCP tool results labelled `@cji` by an annotator;
      ai_scrub_proxy declared as the sanitizer with
      `permits = { audience = { from = ["@cji"], to = ["public"] } }`; `tool_result` hook
      answers `replace_output` with the sanitized text.
- [ ] **Default rule: any unlisted tool is a `public` destination.** Plus an explicit
      exception list for enclave-local tools: Read, Edit, and enclave-hosted MCP servers.
      OpenAPPA receives the tool inventory at `session_start`, so a new connector is covered
      by the default with no per-connector config. **Verify the default-rule TOML syntax
      against the contracts page before relying on it.**
- [ ] **Bash needs a decision.** A shell can reach the network, so it isn't enclave-local
      by nature. Options: treat Bash as `public` (safe, noisy), or as enclave-local inside
      the compose stack only, where egress is already allowlisted. Recorded in §8.
- [ ] `appa replay` policy tests in `policy-tests/`: unsanitized → blocked; sanitized →
      allowed; unlisted tool after a `@cji` read → blocked. Run in CI.
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
- [ ] `deploy/desktop/`: managed-settings file for the desktop app that pins
      `ANTHROPIC_BASE_URL`, defines the OpenAPPA hooks, and disables Artifact publishing.
      Include the check that it survives app updates.
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
    AiScrubProxy.Core/             registry loader, shape classifier, rule dispatch, surrogates
    AiScrubProxy.Proxy/            Anthropic-compatible proxy (YARP) + OpenAPPA /sanitize
    AiScrubProxy.Audit/            IAuditSink, durable queue, SQL Server sink, in-memory sink
    AiScrubProxy.Cli/              sanitize / eval / verify
  tools/
    ImportTaxonomy/               NIEM + NIBRS → taxonomy and field-name YAML
  recognizers/
    taxonomy.yaml                 categories and their surrogate prefixes
    fields/                       field-name → category, one file per source
    patterns/                     shape + pattern + validator rules, one file per family
    gazetteers/                   public-domain name lists
  tests/
    AiScrubProxy.Core.Tests/       xUnit, one test class per recognizer
    AiScrubProxy.Proxy.Tests/      pass-through, streaming, feedback note, identity rejection
    corpus/                       synthetic dev artefacts + gold labels (JSONL)
  policy/
    appa.toml                     OpenAPPA policy: default-public, enclave exceptions, sanitizer
    policy-tests/                 appa replay fixtures
  deploy/
    compose/                      claude-code + ai_scrub_proxy + openappa, egress = proxy only
    workstation/                  settings bundle for CLI and IDE extensions
    desktop/                      managed-settings file + update-survival check
  db/
    migrations/                   versioned SQL scripts, applied by a DBA, never by the service
  .env.example                    AI_SCRUB_PROXY_AUDIT_CONNECTION and friends, dummy values
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
- **MCP connectors are open in v1.** OpenAPPA's `tool_result` hook sanitizes data coming
  in from connectors, and the default-public policy rule blocks outbound connector calls
  once a session is tainted. **The gap:** CJI pasted directly into a prompt never passes
  through a tool, so OpenAPPA can't taint the session. The proxy is the only cover for that
  path. Decision recorded; revisit if the proxy's recall numbers don't hold.
- **Cloud sessions and Remote Control carry context through Anthropic's infrastructure
  without touching the proxy.** Left enabled by decision in v1. Same for web search, web
  fetch, built-in browser, computer use, and bypass-permissions mode.
- **No model means free-text names depend on gazetteers plus context.** A name in a
  sentence with no nearby context word will be missed. Accepted: developer artefacts are
  mostly structured, the field-name dictionary covers those, and the trade is a scrubber
  every replacement of which can be explained. The eval corpus reports the free-text
  number so the gap is visible, not hidden.
- **Thousands of rules is a maintenance surface.** Mitigation: rules are data with a
  source field and their own examples, the import tool regenerates the standards-derived
  parts, and CI fails on a rule without a test.
- **False positives on code identifiers will make developers route around the proxy.**
  Mitigation: validators, context requirements, negative examples in the corpus, and
  precision reported per rule so the noisy ones are findable.
- **A sanitizer that passes OpenAPPA's `permits` is trusted to be correct.** OpenAPPA will
  happily forward whatever we return as `public`. Our recall number *is* the security
  boundary. Treat the eval corpus as production code.
- **Delayed audit writes can be lost.** The local queue survives a database outage but not
  a lost proxy disk before the flush. Encrypt the disk, alert on queue depth and age, and
  treat a growing queue as an incident.
- **Compliance claims.** Nothing here makes a system CJIS-compliant. It makes one component
  of a system defensible. Say that in every README.

## 8. Decisions still open

1. Whether the agency has an existing list or data dictionary to seed the registry, or
   whether Phase 2 starts from NIEM and NIBRS alone.
2. How the feedback note reaches the developer: trailing text block in the response, a
   response header the client ignores, or a hook-side message. Decided in Phase 0 once
   we see what each client renders.
3. Whether block mode ships on by default for SID and UCN, or stays opt-in.
4. How OpenAPPA treats Bash: `public` everywhere, or enclave-local inside the compose stack
   where egress is already allowlisted. See Phase 3.
5. Whether Artifact publishing can be disabled by managed settings. Phase 0 answers it;
   if not, it becomes a recorded gap in §7.

## 9. Later, if ever

- **Rehydration.** Swapping surrogates back into Claude's answer. Developers don't need
  real names in Claude's output; they need working code. Rehydration is also where leaks
  happen: a real name goes back in and gets pasted somewhere. Not planned.
- **Streaming rehydration.** Follows from the above. Not planned.
- **.NET agent middleware** (`IChatClient` delegating handler). Dropped. Claude Code is
  the agent; the proxy covers it.
