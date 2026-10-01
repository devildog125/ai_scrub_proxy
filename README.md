# ai_scrub_proxy

An Anthropic-API-compatible proxy, written in .NET, that strips criminal-justice
information (CJI) and other sensitive data from everything Claude Code sends to Anthropic.
Developers point `ANTHROPIC_BASE_URL` at it and keep working. OpenAPPA cleans tool outputs
before the model sees them, and every scrub is recorded in the agency's SQL Server.

See [PLAN.md](PLAN.md) for the purpose, architecture, and build phases.

**Status:** planning. No code yet.

**Compliance:** nothing in this repository makes a system CJIS-compliant. It makes one
component of a system defensible. That determination belongs to the agency's CJIS Systems
Officer and their auditor.
