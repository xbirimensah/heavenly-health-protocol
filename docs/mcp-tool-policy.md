# MCP data tool policy

## Purpose

**Implementation status:** the narrow health-specific tool surface below is
implemented. Generic schema browsing and table-oriented CRUD remain deliberately
unimplemented because they would widen the storage boundary unnecessarily.

Once implemented and explicitly enabled, Heavenly MCP will expose the configured
Heavenly data model through generic, table-oriented actions. It will not be an
unrestricted SQL shell.

The MCP tool surface mirrors the selected Heavenly/Supabase schema after storage setup. A tool can inspect configured tables, their fields, provenance, and normalized health records without the client needing provider-specific tools for every metric.

## Read actions

The following read/status actions become available only after the owner enables a
validated storage adapter:

```text
health_briefing_schedule         # non-secret schedule so an agent can self-schedule
health_connector_status
health_available_metrics
query_health_events
health_daily_state            # explainable recovery band + one action; never diagnoses
health_daily_briefing         # delivery-ready action, evidence, freshness, uncertainty, feedback choices
health_weekly_coaching        # bounded seven-day coaching and coverage gaps
health_feedback_history       # compact outcomes only after local owner approval
health_event_provenance
search_personal_context          # only when an explicit context relation exists
sync_health_source               # only a configured, bounded connector
```

`health_briefing_schedule` returns only the owner's non-secret briefing cadence,
local delivery time, timezone, and the fetch lead (`recommended_fetch_at`,
`fetch_lead_minutes`). It never exposes credentials or storage connection values.
It is available before storage is enabled so an agent can plan its own wake job:
fetch a fetch-lead before `next_briefing_at`, then sync and query.

Health queries require an explicit metric allowlist, timezone-aware start/end,
maximum 31-day window, and maximum 200 rows. `health_daily_state` uses only
fresh, allowlisted recovery signals and a 3–30 day personal baseline. It returns
an explainable action band or `insufficient_data`; it never diagnoses or invents
a composite score. `health_daily_briefing` composes that bounded state into a
stable delivery contract (headline, one action, evidence, data freshness,
confidence, and limitations), rather than asking a delivery agent to invent an
interpretation. Provenance returns source linkage but never the raw payload.
`health_feedback_history` returns only compact owner-approved outcomes, never
raw health values or unapproved feedback. Context search returns bounded previews
from one configured relation. No action accepts SQL, arbitrary relation names,
projections, or URLs.

The initial configured health relations are expected to include:

```text
heavenly_health_events
heavenly_health_raw_events
```

Raw records remain clearly marked as provider payloads and provenance data. The owner can restrict individual tables, columns, or data classes in the storage/MCP policy.

## Write actions

The implemented mutation actions are:

```text
propose_health_event_write
propose_daily_briefing_feedback
execute_approved_health_write
health_mutation_audit
```

A manual health insert is always two-channel:

1. MCP validates one allowlisted event and stores an integrity-signed, owner-only
   proposal with a preview and short-lived `approval_id`.
2. The human owner reviews and approves it through
   `heavenly approval approve <approval-id>` in a local terminal. MCP has no
   approval tool. Only then can `execute_approved_health_write` idempotently apply
   that exact payload once.

Daily briefing feedback follows the same owner-approval boundary. An MCP client
may stage exactly one of `done`, `partly`, `skipped`, or `not_useful` against the
current `recover`/`maintain` state. Local approval makes the compact outcome
available to `health_feedback_history`; no raw health values are written, and an
agent cannot self-approve or claim the feedback was stored.

An AI saying that a write seems useful, or inferring consent from earlier discussion, is never approval. `commit_write` must fail for expired, modified, unapproved, or already-consumed approvals.

## Do

- Use structured filters and schema-aware fields.
- Preserve source identity, provenance, timestamps, synthetic/live markers, and audit history.
- Make insert/update/delete effects reviewable before an owner approves them.
- Limit writes to the configured storage relations and the OAuth scopes granted to the caller.
- Record approval state, redacted preview, timestamps, and result reference in an
  integrity-protected local audit record.
- Use explicit owner approval for every MCP-originated write, including changes requested by a scheduled or external AI agent.

## Do not

- Expose a generic SQL execution tool.
- Let an MCP client alter secrets, OAuth credentials, storage connections, tunnel configuration, model settings, or authorization policy through data tools.
- Let writes bypass source/provenance validation or silently turn synthetic data into live data.
- Permit unbounded bulk writes/deletes without an owner-approved affected-record count and diff.
- Treat an OAuth client ID/client secret as approval for a data mutation.
- Commit a write merely because an LLM asked for it or because it appeared in a prompt.

## OAuth scopes

```text
health.read     Read configured health data and metadata.
health.write    Prepare health-data changes; commit only after owner approval.
health.admin    Not granted to MCP clients. Reserved for local Heavenly CLI setup.
```

The owner identity is established during remote setup and is independent of provider subscription, Cloudflare account, and connector account emails.
