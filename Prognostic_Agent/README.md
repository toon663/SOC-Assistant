# Prognostic Agent — Phases 1 and 2

Standalone FORECAST agent: Analyst-correlated alert -> asset context -> technical
impact -> conditional ATT&CK paths -> structured forecast for the Analyst/BI handoff.
Python 3.10+ standard library only. Importing the package performs no I/O.

## Run and verify

From the repository root, replay the included fixture with its explicit cutoff:

```powershell
python -B -m Prognostic_Agent --input Prognostic_Agent/examples/analyst_alert.json --asset-inventory Prognostic_Agent/assets/sample_asset_inventory.json --as-of 2026-11-23T12:00:00Z --environment test --no-llm --no-history
python -B -m unittest discover -s Prognostic_Agent/tests -t . -v
```

Use `--input -` (the default) to read stdin. JSON goes to stdout; diagnostics go
to stderr. Exit codes: 0 = forecast, including an abstention; 2 = invalid Analyst
input; 1 = operational/configuration failure. `--output-dir` optionally writes a
unique JSON file with exclusive creation. Add `--no-history` for compute-only operation;
otherwise the CLI records forecasts and shadow attempts in the agent-owned database.
The default `forecast_as_of` is current UTC; historical examples naturally become
stale unless replayed with `--as-of`. No administrator access or API keys needed.

There is no LLM code, SDK dependency, or network access. `--no-llm`
is accepted explicitly; deterministic explanations are always used.

## Python interface

```python
from Prognostic_Agent import ForecastConfig, build_risk_forecast
from Prognostic_Agent.asset_context import LocalJSONAssetProvider
import json

def main():
    with open('Prognostic_Agent/examples/analyst_alert.json', encoding='utf-8') as f:
        alert = json.load(f)
    config = ForecastConfig(
        environment='test',
        evidence_freshness_limit_hours=24,
        forecast_horizon_hours=24,
        asset_provider_deadlines={'local_json': 2.0},
        enrichment_timeout_seconds=5.0,
    )
    response = build_risk_forecast(
        alert, config=config,
        asset_provider=LocalJSONAssetProvider('Prognostic_Agent/assets/sample_asset_inventory.json'),
        forecast_as_of='2026-11-23T12:00:00Z',
    )
    print(json.dumps(response, indent=2))

if __name__ == '__main__':
    main()
```

Providers run in isolated `spawn` processes so an uncooperative lookup can be
terminated. Executable callers need a `__main__` guard; custom providers must be
picklable classes in importable modules. Notebook-local classes are unsupported.
Use `asset_providers=[...]` for multiple providers. Priority follows list order;
a fresh fallback can replace a stale record. Completed entities are streamed
back and retained on timeout. The per-provider budget includes process startup;
total enrichment defaults to five seconds, plus bounded process cleanup.

The public lower-level functions are `enrich_asset_context`,
`analyze_risk_impact`, and `forecast_risk_path`. They accept normalized alert
dicts and the explicit context/configuration inputs used by `build_risk_forecast`.
The package imports neither `backend` nor `Sentinel_Agent` nor `Event_Gatherer`.
Those integrations require a separate approved change.

## Analyst contract

`schemas/analyst_alert.schema.json` documents the structural request contract;
`contracts.AnalystAlert.from_dict` additionally enforces unique identities,
resolved references, timezone offsets, and finite JSON values. Empty evidence
arrays are accepted and produce an abstention. Required scalar fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer 1 |
| `alert_id`, `analyst_revision` | Nonempty strings |
| `timestamp` | Analyst assessment timestamp with timezone |
| `anomaly_score`, `triage_score` | 0–100; triage score excludes asset impact, or is null when unavailable |
| `analyst_confidence` | 0–1 evidence confidence |
| `verdict` | `benign`, `suspicious`, `malicious` |
| `entities` | Full entity list: unique `entity_id`, `entity_type` (`user`, `host`, `service`) |
| `normalized_events` | Unique `event_id`, timezone-aware `timestamp`, `event_type`, `entity_ids` |
| `observed_techniques` | Unique `technique_id` and `evidence_refs` to supplied events |

Optional: `request_id`, `user_id`, `host_id`, `source_ip`,
`correlated_alert_ids`, and string-array `findings`. Primary users/hosts must
appear in `entities` with the corresponding type. Additional JSON evidence fields
are preserved for hashing, not interpreted as instructions. The agent does not
correlate/deduplicate alerts, obtain threat intelligence, or query IP reputation.

Input fingerprints use SHA-256 over UTF-8 JSON with sorted object keys, compact
separators, finite numbers, normalized UTC timestamps, numeric score types, and
sorted unordered entity/event/technique/reference/finding collections.
`request_id` is excluded as transport metadata. Evidence content, Analyst
revision, and all other supplied fields participate. Input dictionaries are
copied and never mutated. This is the package's canonical normalization, not
a claim of RFC 8785 implementation. Configuration/rule/weight hashes are separate.

Invalid Analyst input returns `response_type: validation_error` with
`schema_version`, nullable `request_id`/`alert_id`, and `errors[]` entries
(`field`, `code`, `message`). It never contains forecast status or risk scores.
Configuration/rule failures return a distinct `operational_error` envelope.
Every forecast, validation error, operational error and CLI report includes
`schema_version`, `agent_version`, `config_version`, and `versions` with config,
rule and weight versions/hashes. An unreadable or unversioned artifact has a null
version plus a `provenance_issues` entry, never an invented version. Current agent
version is 0.2.8 and config version is 3. Use `--rules-path` / `--weights-path` to
select alternate versioned artifacts. The engine preserves loaded artifact hashes.

## Analyst-to-Prognostic adapter

`analyst_adapter.adapt_analyst_incident(serialized_incident, behavioral_score=None,
technique_evidence=None, guard_context=None)` imports no backend code. It maps `incident_id` to
`alert_id`, extracts nested Analyst fields, normalizes Windows user/host identity
case and type prefixes, builds the full entity list available in supplied events,
and retains finding text/contributions. It does not turn a provider/destination
string into a service entity; only explicit `metadata.service_name` supplies one.

`analyst_revision` is `triage:<UTC triaged_at>:<assessment hash prefix>`.
Changes after a review change the revision even if `triaged_at` is unchanged.
Missing/invalid `triaged_at` is an issue and yields request validation errors;
it is not replaced by the current clock. Correlation summaries with no incident
ID and related evidence/entities that were not supplied are reported as gaps.

The backend Analyst exposes `risk_analysis.behavioral_score`: the bounded 0-100
rule score before any high-criticality bonus, retaining the existing benign cap.
Its existing `risk_analysis.risk_score` still includes the high-criticality bonus
where applicable. The adapter consumes the structured behavioral score
automatically; an explicit `behavioral_score` argument takes precedence.
For legacy incidents without either input, `triage_score` is null with a
`behavioral_score_missing` issue. It never subtracts points by matching finding
text or reuses the total. A supplied numeric zero remains a known score.

If a completed Claude review changes the existing rounded total, the review
merger sets `behavioral_score: null` and `behavioral_score_stale: true`, without
recomputing it. Unchanged totals do not invalidate the score or clear a previous
stale marker. The adapter treats stale scores as unknown even if a numeric field
or explicit override accompanies the marker. A malformed stale marker also fails
closed. It emits `behavioral_score_stale` and the existing missing-score issue;
adapter metadata retains the stale flag and source. Only a new trusted assessment
can supply a fresh behavioral score. Legacy payloads lacking the marker continue
through the existing optional-field fallback.

Alongside its unchanged flat `mitre_techniques` list, Analyst now exports
`risk_analysis.technique_evidence={technique_id: [event_id, ...]}`. Primary-record
rules reference the inspected record. Aggregate/correlation rules reference the
actual supporting records, including related records outside the incident.
Only techniques remaining in the flat list are exported, so benign detections
that clear that list also return an empty attribution map. Attribution names the
observed technique evidence; correlation summaries retain its broader context.

The adapter automatically consumes the map; an explicit `technique_evidence`
argument takes precedence. Only nonempty maps to supplied events are accepted as
exact attribution. Legacy techniques without attribution, malformed attribution,
or references to records absent from the request remain `attribution: coarse`
with empty `evidence_refs`. Missing referenced IDs appear in the issue's
`unavailable_event_refs`. Even mixed present/absent refs stay coarse; the adapter
does not silently discard missing support, invent an event, or fetch related
incidents. Both input sources are recorded in adapter provenance.
Coarse-only techniques cannot seed an
event-bound path, so the agent abstains until attribution is available. Adapter
issues propagate into the forecast. `--analyst-incident` enables translation on
the CLI; `--behavioral-score` supplies the explicit score when known.

Optional `guard_context` is copied from the explicit adapter argument or from
`risk_analysis.guard_context`, with provenance retained; it is never derived from
finding text, scores, or flat technique IDs. The current backend does not produce
these structured assertions. A trusted caller must supply the complete event
bundle and assertions before authentication guards can pass. Direct JSON input
may supply the same request field; runtime validation rejects malformed context.

## Asset records and deadlines

The local adapter reads `schema_version: 1, entities: [...]`. Each record has
`entity_id`, `entity_type`, and timezone-aware `as_of`. Context fields:

- `canonical_id`: optional identity alias used to count scope once.
- `asset_criticality`: `low`, `normal`, `high`, `critical`, or unknown/null.
- `asset_owner`: descriptive ownership, not a score factor.
- `privilege_level`: effective privilege in the observed context: `none`, `user`, `admin`, `system`, or null.
- `platform`: `windows`, `linux`, `macos`, or null.
- `exposure`: `internal`, `internet`, `isolated`, or null.
- `related_assets`: explicit inventory relationships with target `entity_id`,
  `entity_type`, `relation`, `reachable` boolean, and `evidence_ref`.

Effective privileges must describe the observed entity/session, not the maximum
privilege ever associated with an account. Candidate prerequisites can only
combine entities co-occurring in the same supporting event. Future/stale asset
records cannot establish prerequisites. Snapshot freshness defaults to 24 hours
independently of evidence freshness and forecast horizon.

Potential targets require a `can_access` relationship, `reachable: true`, and a
candidate that actually uses that relationship. This asserts reachability, not
confirmed remote authorization or compromise. Missing relationships are unknown;
an empty list represents known absence in that inventory snapshot.

## Candidates, scores, and abstention

The initial rule set has three local hypotheses:

1. T1078 -> T1059.001: valid account -> PowerShell opportunity (user privilege).
2. T1059.001 -> T1003.001: PowerShell -> LSASS access opportunity (admin privilege).
3. T1003.001 -> T1021.002: credential access -> SMB opportunity (admin + reachable host).

Rules include MITRE technique references, platform, prerequisites and rationale.
These edges are local forecasting policy, not MITRE-endorsed transition rates.
ATT&CK tactics are not an ordered chain. Host protections and remote
authorization remain explicit assumptions. Future privilege gains are never
assumed. A remote transition terminates expansion because target privileges
have not been established. Expansion is cycle-free and bounded to three future
steps; return at most three candidates, ordered by conservative score, then
shorter path and stable candidate ID.

A parent-source rule matches its sub-techniques by default (T1078 covers
T1078.003). Set `include_subtechniques: false` for exact-only matching, or provide
`excluded_subtechniques` to deny named children. A sub-technique-source rule never
matches its parent or siblings. Candidates preserve the actual observed ID.

### Rule-schema guard support and opt-in authentication rule

`schemas/transition_rules.schema.json` and the standard-library runtime validator
support rule-document schemas 1 and 2. Existing checked-in rules remain schema 1
with the same content/version; weights are unchanged. Schema 2 adds `guards`
(an array of typed declarations) and `terminal` (a boolean). Empty/absent guards
preserve existing prerequisites. `terminal: true` stops expansion after an
otherwise admitted target; it does not satisfy any prerequisite.

| Guard type | Required parameters | Required evidence |
| --- | --- | --- |
| `exact_attribution` | None | Fully supplied event support for the observed technique |
| `evidence_freshness` | Positive finite `max_age_hours` | Evidence freshness at the forecast cutoff, independent of horizon |
| `analyst_correlation` | Positive integer `minimum_events`, positive finite `window_hours` | Analyst-established grouping/count/window, without new correlation by Prognostic |
| `authentication_reachability` | None | The relevant source can reach the authentication endpoint, not generic SMB reachability |
| `account_authentication` | None | The named target account can authenticate, accounting for known blocking controls |
| `target_not_observed` | None | Avoid forecasting a destination already asserted as observed |

All six evaluators are deterministic and use supplied evidence only. Missing,
unknown, stale, future-dated or inconsistently bound facts return
`guard_<type>_unresolved`; explicit negative facts return `guard_<type>_failed`.
When no path survives, existing abstain reasons are `prerequisites_unresolved`
or `prerequisites_failed`. Supported paths can remain partial when another
transition fails an unresolved guard. Admitted steps and rejected transitions
include `guard_evaluations` with status, reason and supporting references;
assertion-based guards also retain source, timestamp and bound subject. Passed
guard references are included in the candidate's evidence list. Guards generate
no scores and change no weights. An unobserved intermediate technique cannot
inherit the original seed's proof. `minimum_privilege: none` does not require an
already-authenticated privilege; stronger prerequisites remain unchanged.

`schemas/guard_context.schema.json` defines optional request `guard_context`,
version 1, with `bindings[]`. Each unique `(technique_id, seed_event_id)` binding
names `user_id`, `host_id`, `source_ip` and opaque authentication `endpoint_id`.
The user/host must occur in the seed, and the source address must match its
evidence. Assertions belong to this one subject; duplicate/ambiguous bindings
are rejected. Each assertion supplies `source`, timezone-aware `as_of` and
`evidence_refs` to records actually in the request. Host/account/source mismatches
cannot satisfy guards. Facts and supporting evidence must be fresh at the cutoff,
using the stricter of configured evidence freshness and the declared guard limit;
assertions cannot predate their evidence. These limits are independent of horizon.

- `analyst_correlation` asserts `activity`, `event_count`, `window_start` and
  `window_end`, from source `analyst`. The seed must belong to the grouping, all
  counted events must be supplied, and their timestamps must support its bounds.
  The evaluator verifies the declared count/window threshold without constructing
  new correlations. Activity must be `online_authentication_failures`; offline
  password cracking fails and unknown activity stays unresolved.
- `authentication_reachability` asserts boolean/null `reachable` for the named
  source and authentication endpoint. A generic inventory `can_access` link
  cannot substitute for this assertion.
- `account_authentication` asserts boolean/null `enabled`, `locked` and `blocked`
  for the bound account/endpoint. Passing requires true/false/false respectively.
  `blocked` includes known authentication-policy/MFA restrictions preventing use.
  A known disabling/locking/blocking state rejects even if another state is unknown.
- `target_not_observed` rejects an already-asserted target, including coarse
  parent/sub-technique assertions. It conservatively checks the whole supplied
  incident rather than reclassifying an observed destination as a future event.

Source strings record provenance, not authentication: callers must authenticate
and authorize upstream producers. This library does not verify producer identity,
query accounts, infer MFA bypass, or connect to authentication services. A schema
declaration by itself never certifies any fact. Unknown types/parameters, duplicate
types, expressions, invalid bounds and non-boolean terminal flags are rejected.
Guard/terminal fields in schema 1 and unknown rule fields are rejected instead of
silently ignored. Direct in-memory rule calls are validated too. The separate
`rules/attack_transitions_guarded_auth.json` bundle (schema 2, `phase2.1-auth`)
adds T1110 -> T1078 alongside verbatim copies of the original three rules. Select
it explicitly with `--rules-path`; the default rule bundle remains unchanged.
The new edge requires all six guards, at least five supplied online-failure
records within one hour, and terminates at T1078. It excludes T1110.002 password
cracking. Production inventory/provider schemas are unchanged.

The candidate index weights evidence confidence .35, prerequisites .25,
privilege fit .20, reachable target support .15, and evidence recency .05.
Unknown optional factors produce a lower/upper range; the lower bound determines
eligibility. Mandatory unknowns reject the edge. A path uses its minimum edge
index, not a product of uncalibrated probabilities. `probability` is always null.

**`likelihood_index` ranks candidate paths; it is neither a severity measure nor
a probability.** It does not depend on the behavioral score (`triage_score`) or
the combined `risk_score`. Holding Analyst confidence, verdict, evidence and
asset context fixed, changing only the behavioral score leaves candidate indices
unchanged. Analyst confidence is a separate input from behavioral score; changing
confidence or verdict can affect scoring or forecast eligibility. A high index
does not imply a high-consequence destination technique.

`risk_score = .60 * triage_score + .40 * max_known_asset_criticality`, where
criticality maps to 25/50/75/100. If all asset criticalities are unknown,
`risk_score` is null; it is also null when the behavioral score is unavailable.
Partial context is identified explicitly; this score is
based on known assets, not a claim to quantify unknown impact. A benign verdict
caps risk at 20 and cannot seed an attack forecast. `anomaly_score` is provenance
only, avoiding a second contribution from evidence already scored by Analyst.
No money/downtime estimates or response actions are produced.

`confidence.value` is Analyst confidence times fresh asset-field coverage times
candidate factor coverage. It is a deterministic quality indicator, not a
calibrated attack probability. Asset owner is included only in completeness,
never as a numeric risk factor.

Forecast statuses always have `reason` and `reason_detail`:

| Status | Criteria |
| --- | --- |
| `complete` | At least one accepted path; required assessment context and factors resolved |
| `partial` | Supported path remains, but context, evidence, or rule coverage is incomplete |
| `abstained` | No accepted path |

`partial` with `reason: candidate_coverage_incomplete` means that a supported path
remains but some starting techniques have no enabled rule, mandatory prerequisites
for other transitions are unresolved, optional candidate factors are unknown, or
adapter-reported evidence/attribution gaps remain. Coarse attribution and absent
related evidence can therefore produce this reason even when the selected path
has exact evidence and fresh asset context. It is not an explanation failure or
a probability. Asset lookup/context failures and a missing behavioral score use
their more specific partial reasons. Unsupported extra techniques do not erase
otherwise supported paths; when no eligible path remains, the result is abstained
with the applicable abstain reason instead.

Abstain reasons: `insufficient_evidence` (including benign Analyst verdict or zero Analyst confidence),
`stale_evidence` (no event within the cutoff, including future-only evidence),
`unsupported_transition`, `prerequisites_unresolved`, `prerequisites_failed`, or
`below_candidate_threshold` (default .50). Unknown mandatory asset context can
cause abstention even after a lookup timeout. Abstentions have null selected
path/likelihood, retain independently supported impact, and never mean contained.

**On an abstained result, `risk_score` is an impact-only assessment, not a path
forecast or probability.** It retains the documented behavioral-severity/asset
impact calculation when those inputs are known; it is not multiplied by a path
likelihood. `risk_score_basis: impact_assessment_only` makes this explicit.
Unknown behavioral input leaves that combined score null while any known asset
impact remains in `impact_assessment.technical_impact_score`.

Exactly when an **abstained** forecast retains a numeric `risk_score`:

| Behavioral input | Asset criticality at `forecast_as_of` | Result |
| --- | --- | --- |
| A validated, asset-independent `triage_score` is supplied (including zero) | At least one resolved record is fresh, not future-dated, and has known criticality | Retain the weighted score, even though the agent abstained from selecting a path |
| Missing/unknown behavioral score | Any asset context | `risk_score: null`; known asset-only impact can still be returned separately |
| Supplied behavioral score | No usable known criticality: all records absent, invalid, stale, future-dated, or unreturned after timeout | `risk_score: null` |
| Supplied behavioral score | Some assets unresolved, but at least one usable known criticality remains | Retain the score based on the maximum **known** criticality; incomplete coverage remains explicit |

Both numeric components must exist even if a configured weight is zero. The
defaults compute `.60 * triage_score + .40 * max_known_criticality_score`;
criticality maps low/normal/high/critical to 25/50/75/100. A benign verdict caps
the retained score at 20 (or the configured cap). Missing owner, privilege,
platform, exposure or reachability can block paths without necessarily nulling
impact: those fields are not required to calculate the impact-only score.

The particular abstain reason does not itself clear the score. Unsupported
techniques, stale event evidence, missing path prerequisites, low candidate index,
or a benign verdict can all coexist with a retained impact-only assessment when
the two inputs above are present. Event freshness and asset-snapshot freshness are
separate checks. Neither `anomaly_score`, event severity, nor the Analyst's combined
total is substituted for an unknown behavioral score. A numeric zero is not null.
Validation/operational errors are separate envelopes, not abstained forecasts;
they do not expose a top-level `risk_score`.

Every defined `risk_score` output (including nested impact assessments, shadow
metrics and incident summaries) includes `behavioral_score_source: supplied | unknown`.
`supplied` means an asset-independent behavioral score was provided under this
contract; `unknown` means that provenance was unavailable. The adapter never
labels the Analyst's combined total as supplied behavioral input. This field does
not mean the FINAL score excludes asset impact: `risk_score_may_include_asset_impact`
explicitly marks the combined score. Legacy history is conservatively marked
`unknown`, with any existing numeric score marked as potentially including impact.

`numeric_assessment_status` (`complete`, `partial`, `unavailable`) is independent
of `explanation_status` (`deterministic`, future `llm`, or `unavailable`). Phase 1
always supplies a deterministic explanation. A later explanation failure must
not imply incomplete numeric work.

Blast radius uses every supplied entity (including non-primary users, hosts,
services), canonical identity union, and targets from all accepted paths before
the display top-k limit. Potential targets are limited to 100 by default, with
explicit truncation. One inventory relationship hop is supported initially.
Counts separate observed from potentially reachable entities; neither means
confirmed compromise. Missing/stale topology is reported. Per-request unsupported
starting techniques are returned with evidence references and rule version.
Technique syntax is validated; identities outside the small local vocabulary
are not certified against a downloaded ATT&CK catalogue.

## Forecast history and shadow reporting

Phase 2 owns `storage/forecast_history.db`, separate from `soc_agents.db`.
`ForecastHistory` uses WAL, a configurable busy timeout (5000 ms default), foreign
keys, and a first transactional migration recording schema version 1 in
`schema_migrations`. Migration 2 adds environment-scoped history and durable
unsupported aggregates, backfilling legacy records as `demo` without changing
their IDs or historical versions. Migration records tag the initiating environment;
legacy provenance cannot be inferred beyond the conservative demo assignment.
Transactions serialize cross-connection idempotency checks
and monotonic per-environment, per-alert revision allocation. A schema newer than the running agent
is rejected. Revision counters survive retention purges to avoid reusing revisions.
The backend filename `soc_agents.db` and databases with unrelated existing tables
are rejected before migrations, preventing accidental reuse of application storage.

The pure `build_risk_forecast` interface still performs no history writes. For
persisted assessments use `ForecastService(history, config=..., summary_writer=...)`.
The optional writer receives only `forecast_summary(response)`; history writing
never opens backend storage. A writer failure leaves saved history intact and returns
a delivery issue. History write failures return an operational error identifying
any computed result and whether it was persisted.

Default persisted input contains evidence references/hashes, not event bodies or
findings. Full normalized input requires `store_full_evidence=True` (CLI:
`--store-full-evidence`). The config and history object settings must agree.
Default retention is 90 days (`--retention-days`); it is enforced on service
assessment and explicitly by `purge`. Expiry uses ingestion time, not historical
replay timestamps. Purging is scoped to the history object's environment and
cascades through raw unsupported records and linked attempt logs. It preserves
durable per-environment/technique/reason counts, distinct-alert counts, first/last
ingestion time, version sets and confidence count/mean. Only opaque alert and
assessment hashes needed for distinct counting/replay suppression survive with
those aggregates; raw alert IDs and evidence references expire with history.
Recreating a purged assessment does not inflate its aggregate count. Retention
deletion is logical SQLite deletion, not secure media erasure. Data already purged
before migration 2 cannot be reconstructed.

Idempotency identity contains the canonical input fingerprint, engine/config/rule/
weight versions and hashes, explicit `forecast_as_of`, and optional `evaluation_id`.
Changing only `request_id` reuses the saved forecast and logs a new delivery attempt.
Changed evidence/revision/config/rules, cutoff, or evaluation ID creates a revision.
When no cutoff is supplied, a replay returns the original forecast and original
cutoff; it does not silently compute a fresh horizon. Use a new `evaluation_id` or
explicit cutoff to reassess unchanged input against a new asset snapshot. Cached
assessments retain their original provenance and are marked `idempotent_replay`.

Every assessment attempt logs identities/revisions/fingerprints,
versions and horizon; statuses/reasons; missing/stale context and entity coverage;
unsupported techniques and rejection reasons; generated/eligible path counts;
score factors/ranges/confidence; scope/truncation; stage/total latency and provider
timeouts/errors/fallbacks. Validation and engine operational errors are logged too.
An unavailable database cannot log its own write failure; that failure is returned
explicitly. `legacy` comparison fields are optional caller-supplied shadow data;
ATT&CK path differences use `legacy.attack_path`. BI/playbook differences are only
recorded if supplied, never executed. Outcome-window/coverage/intervention fields
exist from day one with unknown values; no negatives or predictive accuracy are
inferred from absent follow-up. Shadow summaries provide counts and p50/p95/p99
latency. LLM metrics are zero/disabled in this phase.

Unsupported reports group no-outgoing-rule/platform gaps by technique/reason and
include durable unique assessment counts, distinct alert counts, first/last ingestion time,
agent/config/rule/weight versions and confidence summaries. `retained_forecast_count`,
raw alert/evidence IDs and the individual confidence list describe only unpurged
history. Redelivery does not inflate counts; a new evaluation identity does. Syntactically invalid technique inputs
are validation attempts counted separately in `shadow-report`; no fabricated ID
is entered into the technique catalogue. JSON and CSV exports create new files
exclusively, avoiding silent overwrites.

All stored application/aggregate/counter records have an `environment` tag:
`test`, `demo`, or `production`. CLI and library default to `demo`; set
`--environment production` or `ForecastConfig(environment='production')` and
`ForecastHistory(..., environment='production')` explicitly. Config and history
must agree. Environment is part of replay identity, revisions and reads; identical
alerts in test and production cannot reuse each other's forecast.

History, shadow reports and JSON/CSV exports default to the selected environment.
`--report-environment test|demo|production|all` overrides only the report filter;
`all` never becomes a stored tag and rows remain grouped by environment. Python
report/export methods accept the same `environment=` filter. Purge uses
`--environment`, not the report filter. `.gitignore` covers the storage directory
and alternate `*.db`, `*.db-wal`, `*.db-shm` (also SQLite/SQLite3 suffixes).

```powershell
# Persisted forecast; omit --no-history (default DB is inside Prognostic_Agent).
python -B -m Prognostic_Agent forecast --input Prognostic_Agent/examples/analyst_alert.json --asset-inventory Prognostic_Agent/assets/sample_asset_inventory.json --as-of 2026-11-23T12:00:00Z --environment test
python -B -m Prognostic_Agent history --alert-id example-alert-1 --environment test
python -B -m Prognostic_Agent shadow-report --environment test
python -B -m Prognostic_Agent unsupported-report --report-output Prognostic_Agent/forecasts/unsupported.json --environment test
python -B -m Prognostic_Agent unsupported-report --format csv --report-output Prognostic_Agent/forecasts/unsupported.csv --environment test
python -B -m Prognostic_Agent purge --retention-days 90 --environment test
# The report filter can be set explicitly without changing the stored tag:
python -B -m Prognostic_Agent shadow-report --environment test --report-environment test
```

All commands accept `--history-db` for an alternative agent-owned history file.
History never writes `soc_agents.db`; the batch replay command below reads it
explicitly in immutable/read-only mode. Tests create temporary databases/exports
inside this package and remove those temporary fixtures after each test.

## Batch replay of persisted Analyst incidents

```powershell
python -B -m Prognostic_Agent batch-replay --backend-db backend/soc_agents.db --limit 20 --history-db Prognostic_Agent/storage/batch_replay.db --output-dir Prognostic_Agent/forecasts/batch-replay
```

This command runs the existing adapter over up to N persisted incident payloads
and writes forecasts/attempts with **environment=demo only**. It prioritizes
Analyst `suspicious`, then `malicious`, then `benign`, then unknown verdicts; within
each group the newest persisted incident is selected first. It includes incomplete
legacy records instead of silently dropping them: missing Analyst fields appear
as validation errors. `--limit` accepts 1–10000 and defaults to 20. The history path
and optional results-export directory must resolve inside `Prognostic_Agent/`.
`--no-history`, a non-demo environment and a single global behavioral-score override
are rejected. Each incident keeps its own known/unknown behavioral provenance.

By default each valid request is replayed at its **stored Analyst triage time**.
Missing/invalid triage times remain validation failures; no timestamp or evidence
attribution is manufactured. `--as-of` explicitly overrides the evaluation cutoff
but does not repair invalid request timestamps. `--asset-inventory` can use an
existing compatible inventory; the replay does not discover assets, call the LLM,
or enrich IP reputation. Without an inventory, context gaps are expected.

The source is opened with SQLite `mode=ro&immutable=1` and `query_only=ON`, so the
reader cannot create backend WAL/SHM/journal files. A nonempty source WAL or rollback
journal is refused because immutable mode would otherwise miss pending WAL data;
provide a stable checkpointed snapshot instead. The command never checkpoints the
backend. SHA-256 is compared before/after selection; if the source changes, replay
stops before opening its history writer. Do not use a changing live database as
an immutable snapshot.

Stdout includes per-run status counts (`complete`, `partial`, `abstained`,
`validation_error`, `operational_error` as applicable), reason counts, available and
selected Analyst verdict counts, issue counts and the top ten unsupported starting
techniques. These counts describe selected deliveries in this run, not lifetime
aggregate counts. Re-running the same snapshot/cutoffs reuses saved forecasts and
records another attempt. `--evaluation-id` requests a distinct evaluation.

Forecasts and attempts are persisted to the demo history database. With
`--output-dir`, a uniquely named JSON manifest additionally contains full forecast/
error responses, adapter issues, source payload hashes and the summary. It does
not export raw incident event bodies. `--store-full-evidence` explicitly opts into
full normalized input in history as with normal forecasting. An exit code of 1
indicates a source/configuration failure or an operational error in the batch;
per-record validation failures remain visible in the summary and are not hidden.

## Inventory proposal only — not implemented

The local adapter already accepts flat `privilege_level`, `platform`, `exposure`,
record `as_of`, and `related_assets`. The real backend context does not populate
enough of them. Proposed minimal additions/population requirements:

| Need | Minimum inventory representation | Proposed change |
| --- | --- | --- |
| Privilege | On each host, `access_grants[]` with `principal_id`, effective `privilege_level`, `as_of`, `evidence_ref` | New host-scoped grants, so admin on one host is not treated as admin everywhere |
| Platform | Host `platform`: windows/linux/macos or null | Populate the existing field from inventory; do not infer it from account names |
| Exposure | Host `exposure`: internal/internet/isolated or null | Populate the existing field, with record freshness and a new `context_evidence_ref` identifying the inventory snapshot |
| Reachability | Existing `related_assets` target/relation plus `protocol`, `port`, edge `as_of`, and `evidence_ref` | Add service-specific, timestamped reachability; SMB candidates need TCP/445 evidence rather than generic host connectivity |

Host nesting defines the scope of each grant. Grant freshness must describe the
effective account/session privilege at the evaluation cutoff, not historical
maximum privileges. Reachability would become tri-state (`true`, `false`, `null`
for unknown); the current validator accepts only booleans, so null handling would
require a separately approved implementation. Network reachability would remain
distinct from remote authorization. Unknown or stale facts must not satisfy a
mandatory prerequisite. These are documentation proposals only: no inventory
schema, sample inventory, provider validation or rule prerequisites were changed
to implement them. Behavioral-only scores and exact technique evidence attribution
would still need upstream support even with a complete inventory.

## Synthetic end-to-end fixture

```powershell
# Prints the FULL engine response and saves an unabridged JSON file.
python -B -m Prognostic_Agent.synthetic_demo
# Same full saved file, but a short stdout summary:
python -B -m Prognostic_Agent.synthetic_demo --summary
python -B -m unittest Prognostic_Agent.tests.test_synthetic_demo -v
```

`examples/synthetic_powershell/incident.json`, `inventory.json` and `settings.json`
are hand-authored test data. The flow is serialized synthetic Analyst incident ->
`adapt_analyst_incident` -> existing `LocalJSONAssetProvider` -> `build_risk_forecast`.
The fixture declares exact technique/event references for T1078 and T1059.001;
credential access (T1003.001) remains a forecast, not an observed input technique.
The supplied behavioral score is 70; the upstream total of 80 deliberately includes
a 10-point asset bonus and is not used as behavioral input. Existing criticality
75 gives a combined score of `.60 * 70 + .40 * 75 = 72`.

The inventory uses only the existing supported fields: effective admin privilege
for the synthetic account/session, Windows platform, internal/internet exposure,
fresh snapshot times, and a documented reachable file-server relationship. The
test's privilege assertion applies to its single synthetic observed host; it
does not implement the proposed host-scoped production grants schema above.

The runner fixes `environment=test` and replays at `2026-11-23T12:00:00Z`; no backend
code, real logs, endpoint commands, history writes, network requests or LLM calls
are involved. Output files stay under `Prognostic_Agent/forecasts/synthetic/` unless
another directory inside this package is explicitly selected. Five candidates
are retained in this test configuration so the output shows rule 1 followed by
rule 2 as one chain, plus the later reachable-host branch. The highest-ranked
candidate starts at the newer PowerShell observation and forecasts LSASS access.
Tests assert a non-null path, complete/partial status, exact fixture attribution,
both first rules in one candidate chain, and exclusion of the upstream asset bonus.
This changes no production inventory schema, provider validation or transition rule.

## Synthetic contrast set

```powershell
python -B -m Prognostic_Agent.synthetic_contrasts
python -B -m unittest Prognostic_Agent.tests.test_synthetic_contrasts -v
```

The command prints one comparison table and writes full results, exact/coarse
attribution records, a probability audit and baseline factor/ranking explanations
under `forecasts/synthetic-contrasts/`. All runs use `environment=test`, the same
fixed cutoff and unchanged rules/weights. No history, backend, LLM or network is
used. `examples/synthetic_powershell/contrast_variants.json` declares independent
perturbations; a fresh copy of the incident, settings and inventory is loaded for
each variant. An in-memory fixture provider uses the existing provider interface;
no production asset schema or scoring behavior is changed.

Contrasts include all five requested factors and two extra failure controls:

- User-level privilege: lower the account's admin privilege to user. Admin-only
  credential paths are removed, but the valid-account -> PowerShell path remains
  complete. That surviving candidate keeps its own baseline index; the selected
  index is slightly lower only because it originates from the older login event.
- Evidence aged by another 12 hours: still inside the 24-hour window, so the index
  falls by .025 through recency while status stays complete. Impact inputs stay fixed.
- No reachability: mark the known file-server link unreachable. SMB candidates
  disappear and the index falls by .15; a local path remains complete. The current
  model applies the reachability factor to local candidates too, even when it is
  not a mandatory local prerequisite.
- Lower behavioral score: supply 20 instead of 70, with unchanged Analyst
  confidence. Combined risk falls from 72 to 42. Candidate likelihood and status
  do not change because candidate scoring uses Analyst confidence, not triage score.
- Stale asset record: age the privilege-bearing user snapshot to 25 hours old;
  keep the host snapshot fresh. Admin-only candidates disappear, the selected path
  falls back to the older login seed, and status becomes partial. Risk stays 72
  because the fresh high-criticality host still supplies the maximum known impact.
- Evidence aged by another 25 hours: all observations expire. Status is abstained,
  reason is stale_evidence, and likelihood/path are null. Independently supported
  impact remains 72 under the documented abstained-score policy.
- No supplied attribution: explicitly omit the fixture mapping without creating
  event links. Both techniques are marked coarse with empty evidence_refs, and
  the agent abstains with insufficient_evidence. Impact remains independently known.

Tests assert direction **including unchanged values**, candidate removal, and
exact statuses/reasons; they do not force each perturbation to cause abstention.
Every emitted `probability` field is checked recursively for JSON null. Abstained
responses instead have `likelihood: null`; no zero probability is manufactured.

Baseline combined impact score: behavioral `70 * .60 = 42` plus maximum fresh
criticality `75 * .40 = 30`, giving **72**. The upstream combined total of 80 is
not used as behavioral input. Candidate likelihood is a separate calculation.

The selected PowerShell -> LSASS candidate is seeded by the 11:55 observation.
Its index is `.315 + .25 + .20 + .15 + .049826 = .964826`. The three-future-step
valid-account -> PowerShell -> LSASS -> SMB candidate is seeded by the older
11:50 login. Its recency contribution is .049653, so its index is .964653.
It loses on index before the length tie-break applies. The two-future-step
PowerShell -> LSASS -> SMB candidate has the same .964826 index as the selected
path; it loses the tie because it has more future steps. Path indices are the
minimum edge index, not products or numeric length penalties; stable candidate
ID breaks any remaining tie. The report derives these comparisons from the
actual returned candidates rather than substituting expected values.

### Individual factor changes in the contrast set

The table below compares each variant's **selected** path with the baseline's
selected path. Entries are changes in weighted contributions to the index, not
changes to weights. Baseline contributions are evidence support `.315`,
prerequisite satisfaction `.25`, privilege fit `.20`, reachable target support
`.15`, and recency `.049826`, totaling `.964826` after rounding.

| Variant | Evidence support delta | Prerequisites delta | Privilege fit delta | Reachability delta | Recency delta | Selected index | Status / reason |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Baseline | 0 | 0 | 0 | 0 | 0 | .964826 | complete / assessment_complete |
| User-level privilege | 0 | 0 | 0 | 0 | -.000173611 | .964653 | complete / assessment_complete |
| Evidence aged another 12h | 0 | 0 | 0 | 0 | -.025 | .939826 | complete / assessment_complete |
| No reachability | 0 | 0 | 0 | -.15 | 0 | .814826 | complete / assessment_complete |
| Lower behavioral score | 0 | 0 | 0 | 0 | 0 | .964826 | complete / assessment_complete |
| Stale user asset record | 0 | 0 | 0 | 0 | -.000173611 | .964653 | partial / asset_context_incomplete |
| Evidence aged another 25h | N/A | N/A | N/A | N/A | N/A | null | abstained / stale_evidence |
| No supplied attribution | N/A | N/A | N/A | N/A | N/A | null | abstained / insufficient_evidence |

Recency deltas above use unrounded arithmetic. Returned contributions and indices
are rounded to six decimal places, so subtracting `.964653 - .964826` gives
`-.000173`; the underlying delta is about `-.000173611`, or `-.0002` at four
decimal places. N/A means no candidate was scored, not a zero-valued factor.

- **User-level privilege:** privilege is an admission prerequisite here. Removing
  admin privilege removes the LSASS/SMB paths; the remaining login -> PowerShell
  candidate satisfies its user-level requirement, so `privilege_fit` remains
  `1 * .20 = .20`. It has exactly the same index as that same candidate in the
  baseline. The selected path switches from the 11:55 PowerShell seed to the
  11:50 login seed: raw recency changes from `.996527778` to `.993055556`, a delta
  of `-300/86400 = -.003472222`; multiplied by `.05`, this gives `-.000173611`.
  This is a change in the selected candidate, not a continuous privilege penalty.
- **Evidence aged another 12h:** raw recency falls by `12/24 = .5`; its weighted
  contribution falls from `.049826` to `.024826` (delta `-.025`). The selected
  path and all other factors stay the same.
- **No reachability:** raw reachable-target support falls from `1` to `0`, making
  its contribution `.15 -> 0` (delta `-.15`). SMB paths are also rejected. The
  selected local LSASS path remains admissible; the current index includes this
  factor even for local candidates without a mandatory reachability prerequisite.
- **Lower behavioral score:** all five candidate factors stay fixed. Only the
  combined impact calculation changes: behavior `70 -> 20` changes its weighted
  contribution `42 -> 12` (delta `-30`); technical impact remains `30`, so
  `risk_score` changes `72 -> 42`.
- **Stale user asset record:** excluding the old admin snapshot removes admin
  paths. The surviving host context supports the user-level PowerShell path,
  causing the same selection/recency delta as the user-level variant. Fresh asset
  field coverage falls `1 -> .5`, so separate confidence falls `.9 -> .45`.
  This incomplete context causes `partial`; fresh host criticality keeps risk 72.
- **Expired evidence and no supplied attribution:** both abstain before candidate
  scoring. Separate confidence falls `.9 -> 0`; risk stays 72 because the impact
  inputs remain known. Coarse technique attribution retains empty evidence refs.

Except for lower behavioral score, all contrasts retain the impact contributions
`42 + 30 = 72`. Confidence remains `.9` except for the stale snapshot (`.45`) and
the two abstentions (`0`). These confidence changes are not extra candidate-index
contributions. Every emitted `probability` remains null.

### Proposed path consequence options (not implemented)

The following are design options only. They add no output fields, configuration,
weights, destination policies or runtime behavior. Neither option treats the
candidate index as a calibrated event probability or expected-loss multiplier.

1. **Versioned policy matrix (recommended first):** a proposed `path_consequence`
   object would retain the index, impact score/basis, destination technique and
   context, plus a policy-derived priority band and rationale. A matrix would
   combine index bands, impact bands and reviewed destination-effect categories.
   Categories would be local policy with explicit unknown handling, not intrinsic
   ATT&CK severity labels. For this fixture, a proposed policy could assign LSASS
   credential exposure a higher consequence category than PowerShell execution.
   Baseline and user-level variants have effectively the same index band and
   impact (72), but the user-level variant loses the credential-access destination,
   so its selected path would receive the lower category/band. Context and
   mitigations would be needed before adopting that mapping beyond the fixture.
2. **Numeric heuristic for queue priority:** a proposed `path_priority_index`
   could combine `likelihood_index * impact * destination_context_modifier`,
   while exposing all three factors and policy version. For illustration only,
   using existing risk 72 once and hypothetical destination modifiers of `1.0`
   for this LSASS path and `.5` for this PowerShell path gives baseline
   `.964826 * 72 * 1 = 69.47` versus user-level `.964653 * 72 * .5 = 34.73`.
   These modifiers are unapproved examples, not scoring-weight changes. Such an
   index would be a heuristic priority, not probability, calibrated severity or
   expected harm. It would need outcome-based evaluation for ranking usefulness.

Either design must declare its impact basis: existing combined risk (behavior
plus asset impact), or technical asset impact alone. It must use that impact once,
without reapplying criticality or embedding it again in the destination modifier.
For longer paths, start with the selected path's terminal destination and expose
that choice; any later policy using the maximum consequence across steps must be
explicit and must not sum repeated asset impact. Missing impact or unknown
destination policy should yield an unknown consequence with a reason. An abstained
forecast has no selected path, so its path consequence would be null even when
its separate impact-only `risk_score` remains numeric.

## Event-based Sentinel -> Analyst -> adapter smoke test

```powershell
python -B -m Prognostic_Agent.event_pipeline_demo
python -B -m unittest Prognostic_Agent.tests.test_event_pipeline_demo -v
```

This generates seven gatherer-shaped Windows Security records: five failed
logons (4625), one subsequent network logon (4624), and a process launch (4688)
with encoded, hidden-window and execution-policy-bypass PowerShell indicators.
The encoded payload is `Write-Output 'synthetic-only'`. All commands are event
text; no command in the events is executed.

The runner calls the existing `Sentinel_Agent` Random Forest with its existing
model and cached catalog, then the backend's normalization/grouping functions,
`SentinelAgent` and `AnalystAgent`. Sibling incidents are passed as related
events with their actual Sentinel incident IDs. It uses a hand-built local
inventory for Analyst asset criticality and Prognostic asset lookups. It runs
the adapter without behavioral-score or technique-attribution overrides, then
the standalone Prognostic engine with `environment=test`.

The CLI confines filesystem writes to `Prognostic_Agent/` and blocks database
and network connections. It does not use the persistent ingest service, train
or save models, refresh the catalog, collect live events, scan executables,
call an LLM, or execute response actions. Full inputs, inventory, detector
outputs, Sentinel/Analyst incidents, adapter requests/issues, forecasts and
detector warnings are saved under `private/event-pipeline/<run>/`. Source,
model and catalog hashes are checked before/after execution. Existing Sentinel
ML dependencies and the existing local model/catalog are required; this is an
integration smoke test, not a detector accuracy benchmark.

The verified run emits Analyst techniques `T1110.001, T1078` for failed logons,
`T1110, T1078` for the success after failures, and `T1059.001, T1027, T1564.003`
for PowerShell. Analyst's existing total risk scores remain 90, 95 and 95; its
new behavioral scores are 80, 85 and 85. The adapter consumes these without
overrides, eliminating `behavioral_score_missing` for the current pipeline.
PowerShell techniques have exact attribution and yield a `partial` forecast due
to unsupported secondary techniques, with a selected PowerShell -> LSASS path.
The successful-logon incident has exact T1078 attribution and also yields a
`partial` forecast. Its T1110 evidence belongs to the related failed-logon
incident, so that technique remains coarse; the request reports missing related
evidence. The failed-logon incident has exact T1110.001 evidence, but that source
has no enabled outgoing rule, while its T1078 references the related success;
it abstains with `unsupported_transition`. Combined Prognostic risk is 78, 81
and 81 respectively; the abstained 78 is impact-only. Legacy payloads without
the additive Analyst fields retain the earlier coarse/missing-score behavior.
The current
environment warns that the existing model was saved with scikit-learn 1.6.1 but
is loaded with 1.9.0. That compatibility warning is retained in the output; this
smoke test does not establish model validity across those versions.

## Hand-authored authentication lab replay

```powershell
python -B -m Prognostic_Agent.lab_pipeline_demo
python -B -m unittest Prognostic_Agent.tests.test_lab_pipeline -v
```

`examples/auth_lab/inventory.json` contains two Windows hosts and two accounts,
with privilege, owner/criticality, exposure, explicit topology, authentication
reachability, account controls and timestamps. Only the user and workstation in
the event evidence count as observed entities; the unused backup account and
inventory's other host do not inflate the observed blast radius. The file server
is a potential target only where an eligible path supports it.

`examples/auth_lab/guard_assertions.json` supplies hand-authored lab proof and a
clearly labeled inventory-snapshot evidence record. It is fixture ground truth,
not output newly emitted by Analyst. The fixture's `source: analyst` identifies
the asserted grouping role, not authenticated producer identity. The runner
checks the declared cohort against the actual Analyst technique/event map and
resolves record aliases only to actual supplied events. It never overrides
behavioral scores, invents technique attribution or changes a backend incident.
The inventory snapshot is added only to the separate adapter input, after triage;
both the original Analyst incident and augmented adapter input are retained.

All artifacts/forecasts use `environment=test`; nothing is written to forecast
history, backend storage, protected code/model files or external systems. The
runner also checks, read-only, that the eight expected-failure methods match the
accepted scope exactly. A committed scope snapshot supports fresh checkouts;
the historical scope report is additionally checked when available locally.

The same seven synthetic records are replayed at a fixed event-time cutoff for
each incident (its last event plus one second). Analyst receives only related
records already available at that cutoff. `triaged_at` records processing time;
the explicit `forecast_as_of` defines historical evidence/horizon evaluation.
Before the success is visible, the failure group emits T1110.001 without T1078:
behavioral score 50 and impact 75 produce risk `.60*50 + .40*75 = 60`, and the
new guarded T1078 path is complete. Success and PowerShell incidents retain risk
81 with supported partial paths. The lab does not make a known successful logon
disappear to manufacture a forecast: a separate batch control gives Analyst all
seven events, retains its T1078 assertion, and verifies rejection through
`guard_target_not_observed_failed` (impact-only risk 78).

One fact is removed independently from a fresh copy for each incident:

- Failure group: remove the authentication endpoint's reachability fact from its
  inventory/assertion projections. The forecast abstains with unresolved
  prerequisites and retains impact-only risk 60.
- Success: remove the account's admin privilege. The PowerShell opportunity
  remains, but admin-dependent paths disappear, context becomes incomplete and
  potential blast radius falls from one host to zero.
- PowerShell: remove the workstation topology field, representing unknown
  relationships rather than known absence. The local path remains partial, but
  SMB reachability is unresolved, candidate-index support falls by .15, and the
  potential radius falls to zero. Impact stays 81 in both latter contrasts.

Full source/detector/agent outputs, inventory and guard inputs, six forecast
results, exact issues, coverage/rejection diagnostics and the batch control are
saved to `private/lab-pipeline/<run>/lab_results.json`. The printed table combines
issue codes and coverage findings; JSON preserves `issues[]`, unsupported
techniques and rejected transitions as separate fields. Existing detector
version warnings are preserved. Every probability field remains null.

## Offline inventory import and local-export runbook

The shared `importers/core.py` handles source hashing, normalization, validation,
record/section quarantine, provenance and versioned publication. Only the
`local_export` adapter is implemented. It accepts the attached exporter's exact
`local_context_raw.v1` format; it performs no live queries. Both the importer and
the core forecast engine use only the Python standard library. The integration
replay additionally uses the existing Sentinel model and installed ML packages.

Run manually from the repository root. All new runbook examples use
`--environment test` until deployment is approved. First run the reviewed,
read-only exporter, supplying a unique destination inside the ignored `private/`
directory. The exporter has no environment option; the importer tags the output.

```powershell
$rawPath = Join-Path (Get-Location) ('Prognostic_Agent/private/exports/local_context_raw_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '.json')
powershell.exe -NoLogo -NoProfile -NonInteractive -File "$env:USERPROFILE/Downloads/export_local_context.ps1" -OutputPath $rawPath
python -B -m Prognostic_Agent.import_inventory --adapter local_export --input $rawPath --environment test
python -B -m Prognostic_Agent.local_export_pipeline --raw-export $rawPath --environment test
```

On this machine the unsigned attachment required `-ExecutionPolicy Bypass` on
that PowerShell child process after approval. That affects only the child process;
no saved execution policy was changed. Collection failures are quarantined.
The exact exporter message `Group <SID> was not found.` is separately recorded as
`group_not_found`, with `source_status: not_present`, in informational issues.
Permission/RPC/ambiguous errors remain `collection_failed` / `unavailable` and
are quarantined. Group absence does not establish exposure, reachability or
privilege for other groups.

Each import returns paths to a new exclusive directory:
`private/imports/local_export-v1_<UTC>_<SHA-prefix>_<unique>/inventory.json` and
`issues.json`. Reimporting the same bytes produces a separate version; existing
versions and the source are never overwritten. Both documents have
`schema_version: 1`, an environment tag, source/adapter/importer versions, the
source path, collection/import times and the exact source-file SHA-256 (including
any UTF-8 BOM). Every inventory record also has its environment and provenance
with a source JSON locator. The hash detects byte changes; it does not authenticate
the exporting machine or user.

`issues.json` contains `status`, `publishable`, record/canonical-entity counts,
`quarantine[]` and informational `issues[]`. Quarantine entries identify a
document, section or record with `code`, `source_locator`, `detail` and `kind`;
collection failures also identify the source `section`. Invalid documents are
unpublishable. Invalid records and ambiguous aliases are quarantined without
discarding unrelated valid records. All aliases of every colliding record are
excluded. Missing/invalid/future collection times fail closed. Command exit codes
are 0 for a usable inventory (including partial), 2 for quarantined/unpublishable
input, and 1 for source/output errors. Use only a returned publishable inventory.

Mapping rules:

- JSON `null` means unknown; strings such as `"unknown"` are never emitted as
  normalized enum values. Criticality, owner and exposure remain null because the
  exporter does not establish them. Listener bindings and firewall observations
  are source attributes, never proof of exposure or a remote network path.
- `as_of` is the original `collected_at`. `last_updated` is null: the exporter does
  not supply the last modification of the inventory fact. Account `LastLogon` is
  retained only as a source attribute. Import time never refreshes asset freshness.
- Host and local accounts have qualified-name/SID aliases with a shared canonical
  identity. A principal must match an exported local-account SID and a User member
  of this host's Administrators group to receive `privilege_level: admin` plus
  `privilege_scope_host_ids: ["host:<this-host>"]`. Rule prerequisites honor that
  scope; the bare account alias cannot grant admin on another host. A linked
  MicrosoftAccount label still qualifies when its SID is independently verified
  in the local-account export. Contradictory AD/AzureAD source claims are quarantined.
- Domain/external users in the local Administrators group retain null privilege.
  Nested domain groups are retained as observations, with null privilege; group
  members are never invented or expanded. Accounts without verified local admin
  membership retain null privilege rather than an inferred ordinary-user level.
- Known boolean `disabled`/`locked_out` values become account enabled/locked facts;
  absent or malformed values remain null. Policy blocking stays null. The adapter
  emits no reachability edges and omits `related_assets` on every record. Omission
  means unknown topology, whereas `[]` would assert no relationships.

The replay selects an enabled exported local account, preferring verified local
admin membership, and binds the same seven **synthetic** attack events to that
host/account. No PowerShell payload is executed. Synthetic event times immediately
follow the real snapshot, with a causal cutoff per incident; neither source
timestamps nor inventory facts are refreshed. Analyst attribution and behavioral
scores are consumed without overrides. The runner supplies account-control
assertions only for the collected facts; policy blocking and authentication
reachability remain unknown. Full inventory, issues, events, Sentinel/Analyst
outputs, adapter requests/issues and forecasts are saved under
`private/local-pipeline/<run>/local_export_pipeline.json`. Its write guard blocks
network/DB connections and writes outside this agent, and checks protected-file
hashes before/after. It does not write forecast history.

For a caller-saved, complete Analyst incident bundle, a manual shadow forecast is:

```powershell
# Replace the sample paths with the returned version directory and incident file.
python -B -m Prognostic_Agent forecast --analyst-incident --input Prognostic_Agent/private/analyst_incident.json --asset-inventory Prognostic_Agent/private/imports/RETURNED_VERSION/inventory.json --rules-path Prognostic_Agent/rules/attack_transitions_guarded_auth.json --history-db Prognostic_Agent/storage/forecast_history.db --output-dir Prognostic_Agent/private/forecasts --environment test --no-llm
```

Source bundles must contain supporting related events for exact technique attribution. This is
a manual handoff of existing output: no backend hook, watcher or scheduled report
is installed. Forecasts are stored in the agent-owned history database and the
optional JSON directory; raw evidence storage remains off by default. Local export
alone cannot satisfy unknown authentication-reachability/policy guards or business
criticality. Such gaps produce explicit partial/abstained results and may make
`risk_score` null. Existing history/report commands remain available; no weekly
report workflow is implemented by this importer/replay command. The separate
manual daily runner and weekly report are described below.

### AD CSV adapter follow-up (design only)

A future `ad_csv` adapter will feed this same core with an AD user-export CSV and
a host-list CSV. It should map immutable user SID/object GUID and host identity,
namespace, enabled/locked controls, explicit privilege scope, platform and any
source-proven exposure into records. Required IDs and unambiguous host links must
be validated; collisions and invalid identities go to quarantine. Blank or
unrecognized optional values become null with issues. Domain group membership
alone must not imply host admin, privilege, exposure or reachability. Each CSV's
SHA-256, source row/column and explicit export time must be retained. An available
`whenChanged`/`last_updated` can supply update provenance; otherwise it stays null,
separate from export/import time. No CSV adapter, network edge inference or AD
query is implemented in this phase.

## Manual real-event shadow run

Run from the repository root, with the configured Python environment:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File Prognostic_Agent/daily_shadow.ps1
# Inspect resolved defaults without running collection or writing files:
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File Prognostic_Agent/daily_shadow.ps1 -PlanOnly
# Optional preview of a specified local Monday-to-Monday period:
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File Prognostic_Agent/daily_shadow.ps1 -WeekStart 2026-11-23
# Assess only unseen incidents with a triaged_at in the last 24 hours:
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File Prognostic_Agent/daily_shadow.ps1 -FreshOnly -WeekStart 2026-11-23
```

`daily_shadow.ps1` registers no scheduled task and starts no watcher or ingest
service. It uses the reviewed exporter copied into `private/tools/`, the explicit
host-bound `private/operator_overlay.json`, and the existing backend database.
`-ExporterPath`, `-BackendDb`, `-Python` and `-Limit` can override input locations,
the Python executable, and batch size (maximum 10,000). Only inputs can be outside
this agent. Every run artifact, stage stdout/stderr, raw export, effective
inventory, source database snapshot, forecast and report is under `private/`.
An exclusive file lock prevents overlapping manual daily runs. The process-only
PowerShell execution-policy override does not change saved machine policy.

The private operator overlay assigns this host **normal** business criticality,
as explicitly selected by the operator. Host identity must match exactly; there
is no wildcard or user-criticality assignment. Its hash and approval time are
retained as field provenance. It changes no privilege, platform, exposure,
topology, weight or rule. The effective inventory retains the export's original
`as_of`; neither operator approval nor import time makes an old asset snapshot
fresh. Unprovided fields stay null or omitted.

The runner invokes exporter -> `import_inventory --environment test` ->
`operator_overlay --environment test` -> `shadow_batch --environment test` ->
`weekly_report --environment test` -> privacy audit. The exact inventory-file
SHA-256 and the captured UTC run date form the evaluation identity:
`shadow:YYYY-MM-DD:inventory:<full SHA-256>`. The canonical effective-fact hash and
raw export hash are also retained; the evaluation ID uses the exact file actually
read by the provider. Assessment cutoff is the UTC run time. The existing 24-hour
evidence freshness limit and independent 24-hour forecast horizon stay unchanged.
Stored historical incidents are not replayed at old triage time in this mode.

The source database is read as files only. A stable base/WAL pair is copied with
before/after SHA-256 checks, then SQLite recovery/checkpoint/quick-check runs only
against that private copy. Source SHM is not opened or changed. An active rollback
journal or repeatedly changing source fails closed after three copy attempts.
The copy can include committed, uncheckpointed WAL records. No backend code is
imported, and no backend database PRAGMA, ingestion, re-triage, review, response
action or field backfill is performed. `source_inspection.json` reports field
presence, latest triage dates and whether a recent incident is actually available.
The standalone adapter retains its unknown-score/coarse-attribution fallback.
The real shadow runner applies a stricter intake gate: a serialized incident
missing either additive Analyst key (`behavioral_score`, `technique_evidence`)
is `legacy_payload_unsupported`, with the missing keys listed. It is not sent to
the forecast engine and is not a validation error. Present-but-null scores after
review retain the modern contract; key presence is distinct from score availability.
Malformed non-object payloads remain genuine validation errors.

Shadow history is `private/shadow/forecast_history.db`, with WAL, a 5-second busy
timeout and default 90-day forecast retention. A separately versioned table in
that agent-owned database retains hash-only processed keys across purge. Work is
selected by source identity, incident ID and canonical normalized input
fingerprint, before applying the batch limit. Reordered JSON keys and equivalent
UTC timestamp spellings do not cause duplicate assessments. Changed Analyst
input receives a new assessment; a new inventory/day alone does not reassess
already handled input. Validation errors are handled once until input changes;
operational failures remain retryable. After interruption, committed forecasts
and validation attempts repair the processed ledger before new work is selected.
Legacy intake outcomes are also handled once. A versioned classification table
annotates earlier shadow assessment keys, so previously recorded legacy forecasts
and validation attempts can be reported separately without rewriting their raw
stored results. Each source inspection refreshes categories even for rows already
handled or excluded by `-FreshOnly`.
Use another private history database only for an explicitly separate replay.

The earlier `batch-replay` command remains a **demo-only historical** replay. It
is separate from this incremental `shadow_batch` entry point. It is not used by
the daily runner.

### Weekly report and counting contract

```powershell
python -B -m Prognostic_Agent.weekly_report --history-db Prognostic_Agent/private/shadow/forecast_history.db --environment test --output-dir Prognostic_Agent/private/weekly
python -B -m Prognostic_Agent.weekly_report --history-db Prognostic_Agent/private/shadow/forecast_history.db --week-start 2026-11-23 --environment test --output-dir Prognostic_Agent/private/weekly
python -B -m Prognostic_Agent.weekly_report --history-db Prognostic_Agent/private/shadow/forecast_history.db --week-start 2026-11-23 --include-legacy --environment test --output-dir Prognostic_Agent/private/weekly
```

Default period is the **last completed** Monday 00:00 through next Monday 00:00
in `America/Los_Angeles`, start inclusive and end exclusive. An explicit Monday
can select a current-week preview, marked `period_complete: false`. UTC bounds
are derived independently from local midnights; DST weeks may be 167 or 169
hours. Python `zoneinfo` needs the IANA timezone data already installed on this
machine (on Windows, supplied by the environment's `tzdata` package).

Each stored `forecast_id` is counted once by its first persistence time, regardless
of delivery attempts or report reruns. Separate input revisions are separate
forecasts. JSON reports include:

- Forecast status and reason counts; distinct alert count.
- Unsupported technique counts with distinct alert IDs unioned across revisions
  and reason categories, plus separate forecast counts and per-reason distinct
  alert counts. Lifetime/purged aggregates are never substituted for weekly data.
- Abstention numerator, denominator and rate, including rates by reason. The
  denominator is eligible non-legacy risk forecasts: complete, partial and abstained. With no
  forecasts, numerator/denominator are zero and rate is null.
- Separate validation-error and operational-error attempt counts, reason counts
  and details. These errors are excluded from forecast status/rate counts.
  Exporter/importer/source/report failures are recorded as operational attempts.
- Legacy payloads form their own `legacy_payload_unsupported` category and never
  enter validation errors, forecast status counts, unsupported-technique rates or
  the abstention denominator. Default views exclude them from incident lists;
  `--include-legacy` adds their distinct assessment keys and per-incident issues.
  Both views disclose the excluded legacy total. The daily runner emits both
  views. A historical benign/path inconsistency is always surfaced, even if the
  source was later classified legacy.
- Suspicious/malicious incidents with every assessment/error outcome, including
  selected path, risk score, evaluation ID and inventory hash. Unknown verdicts
  are listed separately. Any benign-classified incident with a predicted path
  is surfaced explicitly, even if it came from an inconsistent legacy record.

These are agent assessment outcomes, not verified subsequent compromise; observed
security outcomes remain null. Reports use retained history, so export them
before the relevant source period is purged. Unique report filenames under
`private/weekly/` avoid overwriting previous exports.

### Privacy boundary

`private/` and SQLite/WAL/SHM suffixes are gitignored. Real host/account identifiers
appear only in private inventory, history and run artifacts. Tests and examples
use hand-authored identities. The audit checks local hostname and non-built-in
account tokens from the actual export against `forecasts/`, README, tests,
examples and assets; a match fails the daily run and its report stays private.
It is an explicit token audit, not a general personal-data detector.

Older generated artifacts containing personal identifiers (including absolute
home-directory paths) were moved intact to `private/legacy-forecasts/`. Existing
historical links to the old generated paths may therefore need that archive
prefix. New detector/lab demo defaults and contract-test/integration-test logs
also use `private/`, since even synthetic runs can contain machine-specific paths.
No raw real event is copied into README or test fixtures.

## Re-triage replay of retained incident evidence

```powershell
# Use a freshly exported local_context_raw.v1 file from the local-export runbook.
python -B -m Prognostic_Agent.retriage_replay --backend-db backend/soc_agents.db --raw-export $rawPath --operator-overlay Prognostic_Agent/private/operator_overlay.json --environment test
python -B -m unittest Prognostic_Agent.tests.test_retriage_replay -v
python -B -m Prognostic_Agent.privacy_audit --raw-export $rawPath --backend-db backend/soc_agents.db --output-dir Prognostic_Agent/private/retriage-privacy --environment test
```

This explicit replay mode copies every stored incident's available events to a
versioned disposable SQLite evidence database under
`private/retriage-replay/<run>/temporary-evidence-*/`. It reads a verified private
source snapshot, never opens the backend database with writable SQLite access,
and deletes its working evidence database after processing. Final JSON, CSV and
Markdown reports and a separate agent-owned forecast history remain under that
private run directory. Source/protected-code/model/catalog/rule hashes are
compared before and after. The CLI audit guard permits private writes/SQLite
connections only and blocks network connections. `--store-full-evidence` is the
explicit opt-in for keeping raw event bodies; default artifacts keep evidence
references/hashes and analysis, with the Sentinel message summary hashed.

Events are globally ordered by original UTC timestamp (including Windows'
seventh fractional-second digit), original triage ID and source ordinal. Each
event goes through the current Sentinel RF probe with the existing model and
catalog, threshold .55 and `load_existing_model=True`. Models are neither trained
nor saved. Each accumulating original-incident cohort is passed through current
`SentinelAgent` and `AnalystAgent`; related evidence contains only already-replayed
events on the same host. A final adapter/Prognostic result is produced for every
original incident, including explicit validation-error results. Every result and
stored forecast carries `source: retriage_replay`, `environment: test` and
`original_triage_id` (the original stored incident ID); original `triaged_at` is
kept separately. This is not live ingestion and does not repair the source rows.

The replay re-triages **retained incident evidence**, so it does not discard a
cohort just because the new RF or routine-process admission filter would suppress
it. Those suppressions are reported separately. Windows normalization uses the
current detector output where emitted. The original raw Event Viewer document
was not retained: the RF input is an explicit projection of known normalized
fields. Missing task, keyword, event-data and process/thread fields are recorded
as missing; the detector's own defaults still affect scoring. These RF results
are not a faithful re-creation of the original raw collection. Non-Windows API
events and recorded static-malware findings retain their event semantics. The
Windows RF probe never replaces a PE scanner score, invents a Windows event ID or
adds a malware technique. The recorded static finding is passed to the current
Analyst malware branch; no executable is opened, executed or rescanned.

Only retained events count as observations during replay. An incident with 50
stored events and a larger original occurrence count still has only 50 replayable
events. The original count is reported alongside the replay count; missing or
capped historical evidence is never fabricated. Analyst correlation evidence
actually present in the copied, already-replayed bundle is passed separately to
the adapter when referenced; unavailable attribution remains coarse.

Original event timestamps and fresh inventory collection timestamps are retained.
The Prognostic cutoff is current replay time, so old evidence can still produce
`stale_evidence` even though Analyst triage is newly computed. The operator's
normal criticality overlay remains scoped to the exported host; other historical
hostnames do not inherit it. Unknown asset context can therefore keep risk null.

Replay history is isolated from `private/shadow/forecast_history.db`. Weekly
reporting also checks the source tag: even when explicitly pointed at a replay
history, replay forecasts/errors are excluded from primary counts, abstention
denominators and incident lists, and are shown only in the separate
`retriage_replay` section. Each run writes `weekly_replay_only.json` to demonstrate
that separation. It installs no watcher/schedule and runs no backend Prognostic,
BI, Orchestrator, response action or LLM.

For a replay cohort from other hosts, pass `--backend-db` to the privacy audit.
It copies the source read-only to a disposable private snapshot, adds historical
host/user tokens to the local-export tokens, and checks the same public artifact
areas. Identity values and matching excerpts are never printed.
The generic privilege word `admin` is checked only in explicit identity contexts,
such as a typed user reference or a user-name field; an existing privilege enum is not an
identity disclosure. This remains a targeted token audit, not a general detector
of personal data.

Both repository launchers change into `backend/` and start the same Uvicorn
command without `--reload`; their default database is consequently
`backend/soc_agents.db`, unless `SOC_DATABASE_PATH` overrides it. The dev launcher
additionally sets `SOC_DEV_MODE=1`; the admin launcher does not clear an inherited
dev setting. Changing source files does not reload either launched service.
Current repeat-event ingestion re-runs Sentinel and Analyst over retained old
plus newly ingested evidence, then updates count/first-seen/last-seen and saves.
An exact already-ingested record ID is skipped instead. These are source-code
facts, not proof that an old stored repeat was processed by the latest code.

## Next review gate

Phases 1 and 2 are implemented. Stop for user review before Phase 3.

Phase 3: optional LLM explanation with a configurable ten-second default deadline,
strict candidate/evidence reference validation, no score/ranking/structure changes,
and deterministic fallback. Disabled operation must remain fully functional.
Enabling an SDK will not be required for the core CLI or library.

Future ML training requires timestamped sequence/outcome data and historical
asset snapshots, not static malware labels. Evaluate candidate recall and top-k
quality separately; fit probability calibration on held-out outcomes, split by
time and incident/campaign. Account for interventions and incomplete observation.

Backend integration, changes to existing agents, and automatic response behavior
are outside this implementation authorization.
