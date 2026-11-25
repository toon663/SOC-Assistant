# Prognostic Agent â€” Phases 1, 2 and 3

Standalone FORECAST agent: Analyst-correlated alert -> asset context -> technical
impact -> conditional ATT&CK paths -> structured forecast for the Analyst handoff and proposed Orchestrator integration.
Deterministic mode uses the Python 3.10+ standard library only. Importing the package performs no I/O.

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

LLM explanation is **off by default**. `--no-llm` makes that explicit. Disabled
mode has no SDK, credentials, log writes or network dependency. The optional
Phase 3 explanation layer is described at the end of this README.

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
| `anomaly_score`, `triage_score` | 0â€“100; triage score excludes asset impact, or is null when unavailable |
| `analyst_confidence` | 0â€“1 evidence confidence |
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
version is 0.2.9 and config version is 3. Use `--rules-path` / `--weights-path` to
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
of `explanation_status` (`deterministic`, `llm_selected`, or `unavailable`). Phase 1
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
latency. Disabled LLM metrics remain zero. Enabled calls report timeout/rejection
counts; token usage and cost are null when unavailable, never guessed.

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
as validation errors. `--limit` accepts 1â€“10000 and defaults to 20. The history path
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

## Inventory proposal only â€” not implemented

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

`--causal` evaluates each original incident at its last retained event timestamp.
For that mode only, recorded hosts receive explicit `source: operator_replay`
normal-criticality assumptions at the cutoff. Future observed inventory is
excluded, not backdated: privilege, platform, exposure and relationships stay
unknown. Per-incident inventories are private and do not change live inventory.
`--cohort-report <private previous replay JSON>` fixes the original triage ID set
when the source database has gained incidents since the earlier replay.
Reports include redacted host matching, per-verdict host/incident counts and
per-incident rule/guard/candidate/impact diagnostics. The adapter maps empty,
whitespace, dash and the specified IPv4/IPv6 loopback source-IP placeholders to
null at incident and event level; valid supplied addresses are preserved.

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

## Controlled PowerShell capture procedure (operator-run only)

Failed-logon testing and disposable-account testing are cancelled. Do not run
either. No T1087/T1069 transitions or consequence field are enabled. Optional
Phase 3 explanation remains off unless explicitly requested for a forecast.
`controlled_powershell_test.ps1` is written but was NOT executed by the agent.
It asks for the exact confirmation `RUN PROGNOSTIC CONTROLLED TEST`, then starts
one hidden Windows PowerShell child. Its entire decoded payload is
`Write-Output 'prognostic-controlled-test'`. The child receives `-EncodedCommand`,
`-WindowStyle Hidden`, `-ExecutionPolicy Bypass`, `-NoProfile` and `-NonInteractive`.
The script does not call registry, credential, LSASS, network or Defender APIs.
Only private window/output files are written. Cancelling starts no child.

### Audit observation and optional enable/revert commands

The read-only inspection found the command-line audit registry value absent
(not configured). Effective Process Creation audit policy and recent Security
records could not be read: Windows returned privilege-not-held even outside the
sandbox. Process Creation auditing is therefore **unverified**, not reported off.
Microsoft documents that an unconfigured command-line policy leaves command
lines out of 4688: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-auditsettings

The previous instructions were incomplete: `auditpol /backup` does not save
registry values, and deleting the command-line value on revert assumed its prior
state. Use the operator-only helper below instead. These commands were NOT run.

From an **elevated PowerShell**, at the repository root:

```powershell
# Choose a new private directory. Backup refuses to overwrite an existing one.
$backup = Join-Path (Get-Location) ('Prognostic_Agent/private/audit-backups/' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))
# Read/save both settings first; no audit or registry settings are changed here.
powershell.exe -NoProfile -File Prognostic_Agent/audit_settings.ps1 -Action Backup -BackupDirectory $backup
if ($LASTEXITCODE -ne 0) { throw 'Backup failed; stop' }
# Only when you choose to enable capture:
powershell.exe -NoProfile -File Prognostic_Agent/audit_settings.ps1 -Action Enable -BackupDirectory $backup
if ($LASTEXITCODE -ne 0) { throw 'Enable failed; inspect and restore using the saved backup' }
# Later, use EXACTLY the same backup directory, even from a new shell:
powershell.exe -NoProfile -File Prognostic_Agent/audit_settings.ps1 -Action Restore -BackupDirectory $backup
if ($LASTEXITCODE -ne 0) { throw 'Restore failed; retain the backup and inspect' }
```

Backup saves the current process-creation success/failure flags and registry
value existence, type and value in `settings.clixml`, plus a full audit-policy CSV
for reference. Restore reads that saved state: it restores only the process-
creation subcategory's success/failure settings, and reinstates the original
registry value/type or original absence. It does not restore unrelated audit
subcategories from the full CSV or assume disabled auditing/absent registry values.
A registry key created during Enable may remain empty after Restore; its setting
value returns to its original absence. Keep the saved directory until restoration
succeeds. Operations require elevation and stop on errors; the two-setting update
is not atomic, so an interrupted Enable can require an explicit Restore. Domain
policy may reapply settings later. Command-line capture applies to all audited
processes while enabled. Neither the checker nor daily runner invokes this helper.

Microsoft documents the audit-policy-only scope of
[auditpol backup](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-backup).

Before generating any test event, run this **read-only** check from elevated
PowerShell (it does not enable settings or start the backend):

```powershell
python -B -m Prognostic_Agent.controlled_check --preflight
```

It prints whether process-creation success auditing and command-line capture are
on, whether both are on, Security log maximum/current file bytes, record count,
and the backend listener's start time relative to `backend/analyst.py` as a boolean.
File usage is allocated log file bytes, not occupied event-record bytes. Denied
access and unknown/missing/ambiguous backend listeners are explicitly unverified.
No usernames, hostnames, addresses, PIDs or command lines are printed. The native
audit query uses the subcategory GUID, avoiding localized `auditpol` text parsing.

With a completed `--window`, the check queries raw Security 4688 XML for the exact
encoded payload and time window. It reports one failing capture stage:
`no_4688_in_security_log` (no matching controlled event retained),
`no_incident_ingested` (matching Security event but no stored incident), or
`incident_with_no_technique` (stored incident lacks required T1059.001).
Unreadable Security logs produce an inconclusive diagnosis rather than a false
missing-event claim. A matching incident with a technique but no forecast reports
`not_in_this_batch`; that is an assessment gap, not one of the three capture failures.
A retained incident takes precedence over a subsequently rotated Security log.

### Capture and check

1. Stop the old backend in its owning terminal (Ctrl+C) and restart it so the
   current Analyst module is imported. Neither repository launcher uses reload.
   For this controlled session, use the following manual launch to keep external
   LLM review off and response approval required; the launchers currently set
   LLM review to auto. Run in a separate Administrator PowerShell:

   ```powershell
   $env:SOC_LLM_TRIAGE = 'off'
   $env:SOC_REQUIRE_HUMAN_APPROVAL = '1'
   cd backend
   python -B -m uvicorn api:app --host 127.0.0.1 --port 8000
   ```

2. Enable the existing backend's normal ingestion before the test. Do not approve
   response actions for this inert test. From another repository-root terminal:

   ```powershell
   $rawPath = Join-Path (Get-Location) ('Prognostic_Agent/private/controlled-inputs/local_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '.json')
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File Prognostic_Agent/export_local_context.ps1 -OutputPath $rawPath
   python -B -m Prognostic_Agent.import_inventory --adapter local_export --input $rawPath --environment test
   # Substitute the inventory_path returned by the importer:
   python -B -m Prognostic_Agent.operator_overlay --inventory RETURNED_PRIVATE_INVENTORY_PATH --overlay Prognostic_Agent/private/operator_overlay.json --output-dir Prognostic_Agent/private/controlled-effective-UNIQUE_RUN --environment test
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File Prognostic_Agent/controlled_powershell_test.ps1
   ```

   Confirm the private overlay still says normal for this host. The test script
   records its own start/end time, host, child PID and exact encoded payload in
   `private/activity-windows/`. No collector runs from the controlled script.

3. Wait for an existing ingestion poll or use the existing manual collection UI.
   Select the most recent completed controlled-test window privately, then check:

   ```powershell
   $window = Get-ChildItem Prognostic_Agent/private/activity-windows/*.json | Sort-Object LastWriteTimeUtc -Descending | Where-Object { (Get-Content $_.FullName -Raw | ConvertFrom-Json).kind -eq 'controlled_test' } | Select-Object -First 1
   python -B -m Prognostic_Agent.controlled_check --window $window.FullName
   ```

   A zero match is not success. Check audit policy, ingestion and command-line
   preservation before continuing. No sleeping loop or watcher is installed.

4. Assess fresh ingested incidents, using a second fresh inventory export inside
   the daily runner, then select its most recent summary:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File Prognostic_Agent/daily_shadow.ps1 -FreshOnly
   $daily = Get-ChildItem Prognostic_Agent/private/daily/*/daily_summary.json | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
   python -B -m Prognostic_Agent.controlled_check --window $window.FullName --daily-summary $daily.FullName
   ```

   The check matches the exact encoded payload, host and event-time window using
   a disposable read-only database copy. It prints redacted incident aliases,
   behavioral_score/technique_evidence presence, T1059.001 presence, forecast
   status, reason, path, risk, unresolved guards/prerequisites and issue codes.
   A fresh incident should carry both additive fields and T1059.001 if the
   PowerShell logic actually ran on captured command-line evidence. The full
   three-indicator command scores 45+15+15+10=85 in the current process-creation
   branch, which can label this inert command malicious; no intent is inferred.
   Missing fields/technique or absent ingestion is a failed demonstration.

5. As an additional restart check, in Administrator PowerShell compare the
   listening process's start time to the Analyst source timestamp; print only
   the boolean, not identifiers:

   ```powershell
   $listener = Get-NetTCPConnection -LocalPort 8000 -State Listen | Select-Object -First 1
   $backendProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
   [pscustomobject]@{StartedAfterAnalystEdit=($backendProcess.CreationDate.ToUniversalTime() -gt (Get-Item backend/analyst.py).LastWriteTimeUtc)}
   ```

   A later start supports the restart check; it does not alone attest to source
   bytes. Use the fresh controlled incident's additive fields and technique
   attribution as the functional check. Merely observing pre-existing records
   does not prove that the new code is loaded.

### Data path and known capture limitations

`Event_Gatherer/gatherer.collect_log()` reads Security records without excluding
4688, stores property values in `eventData`, and renders `message` through
`FormatDescription()`. The Sentinel detector retains the message; backend
`windows_ingest.anomaly_to_event()` copies it into SecurityEvent. Analyst
`RULES[(security,4688)] -> triage_process_creation -> message_field('Process
Command Line') -> _score_command -> COMMAND_INDICATORS` recognizes the encoded,
hidden and bypass flags and attributes T1059.001 to the event. It does not read
the named XML CommandLine field directly. Missing/localized rendered message
fields can therefore prevent detection, even if raw property values were read.
The ingest routine-process filter must also admit the event. The current
Sentinel message pattern for PowerShell is narrower than Analyst's (it expects
`powershell -enc`); English token-elevation text can independently match the
privilege pattern. End-to-end admission is to be observed, not assumed.

### Report-only provenance tags

The instrumented export wrapper and daily runner record start/end windows under
`private/activity-windows/`. The daily runner also records importer intervals.
Weekly reporting assigns `possible_self_generated` on same-host incident-span
overlap, and `controlled_test` on controlled-test overlap. These are associations,
not proof of process ancestry; unrelated activity in the same window can overlap.
All `debug-003` and `manual-*` event-containing incidents get `test_data` in
reports only. All three categories are shown in `separated_activity` and excluded
from primary counts/rates, while raw stored verdicts and scores are unchanged.
Tags can overlap and category counts must not be summed as distinct incidents.

Run `python -B -m Prognostic_Agent.activity_tags --backend-db backend/soc_agents.db --history-db Prognostic_Agent/private/shadow/forecast_history.db`
to refresh report metadata for already handled source incidents without replaying
or modifying the backend. Weekly reports also resolve closed windows dynamically
from retained forecast evidence references. Re-run the report after a runner
finishes to include its completed full-run window. Interrupted/unclosed windows
are not treated as completed evidence.

The five historical enumeration records fall inside an inferred exporter window
reconstructed from the raw collection timestamp and file-completion time.
Their caller is WmiPrvSE.exe; parent ancestry was not retained. The supplied
exporter also queries Win32_UserAccount with CIM, consistent with that caller.
This supports possible self-generation, not confirmed parentage. Importer starts
after that interval, so these records are not attributed to importer collection.

The old approval-scope check froze eight expected-failure decorators. Backend now
leaves the re-ingestion/denial audit test undecorated; all eight original methods
remain. Prognostic's historical report remains immutable, but current decorator
drift is reported instead of aborting the unrelated lab. Backend was not changed.

## Phase 3: optional explanation selection

Implemented and disabled by default. The watcher, consequence field, and new
T1087/T1069 rules remain out of scope. The daily runner and all replay/demo
commands continue deterministic-only. No controlled test or audit setting is
invoked by this layer.

The provider is **Anthropic**, using the same `anthropic.Anthropic` SDK as
`backend/llm_analyst.py`. The standalone default is independently configurable:
**`claude-haiku-5-5`**, via `ExplanationConfig(model=...)` or `--llm-model`.
The backend's model/configuration is unchanged. The backend class is not imported:
its triage tools, raw evidence, 120-second timeout and SDK retries are unsuitable
here. The separate setting does not change `SOC_LLM_TRIAGE` or numeric
`ForecastConfig`/config hashes. The SDK reads its normal credential chain,
normally `ANTHROPIC_API_KEY`. Backend comments also mention an `ant auth login`
profile; this agent does not read profiles itself or guarantee support in every
installed SDK version. Missing credentials, SDK or inaccessible model produce
deterministic fallback. No live provider call was used for verification.

Cost trade-off, checked against Anthropic's model overview on 2026-11-24:

| Model | Input / million tokens | Output / million tokens |
| --- | ---: | ---: |
| Haiku 5.5, prompts at most 100,000 tokens | $0.10 | $0.50 |
| Opus 5.5 | $4.00 | $20.00 |

For these short, non-cached requests, those list rates make Haiku about 40 times
cheaper per token. Example only: 1,000 input + 300 output tokens costs roughly
$0.00025 on Haiku versus $0.01 on Opus, before retries or other billing adjustments.
Haiku's larger-prompt tier costs more; these examples do not assume that tier.
The layer only selects existing clauses, so a more capable reasoning model cannot
change analysis or add facts. Whether its choices improve readability enough to
justify any cost requires human evaluation; deterministic mode costs no API tokens.
No actual token usage/cost is inferred from the fake provider. Sources:
[Haiku 5.5 and model comparison](https://platform.claude.com/docs/en/models/haiku-5-5/overview),
[pricing](https://platform.claude.com/docs/en/about-claude/pricing).

Optional installation, only if you choose to enable real provider calls:
`python -m pip install anthropic`. It is deliberately absent from required
requirements. Tests and the comparison use an injected fake provider, no SDK or
network. SDK API/auth reference:
https://github.com/anthropics/anthropic-sdk-python .

Explicit CLI opt-in (this command would make an external call; it was NOT run):

```powershell
python -B -m Prognostic_Agent --input Prognostic_Agent/examples/analyst_alert.json --asset-inventory Prognostic_Agent/assets/sample_asset_inventory.json --as-of 2026-11-23T12:00:00Z --environment test --no-history --llm-explanation --llm-model claude-haiku-5-5
```

Python callers pass `explanation_config=ExplanationConfig(enabled=True)` to
`build_risk_forecast` or `ForecastService`. Providers implement
`complete(request, *, deadline, attempt)` and must be importable/picklable for
Windows spawn. `explanation_provider` is an injection point for offline tests.
Disabled mode returns before provider creation, logging or credential/SDK access.
The existing numeric engine is unchanged; agent code version is 0.4.0a1 (Stage 2a integration components only).

### Enforced explanation boundary

An unrestricted paragraph cannot be mechanically proven free of new claims.
Instead, the model selects/orders approved clauses for **every existing
candidate**. Its entire accepted output is:

```json
{"candidate_comments":[{"candidate_id":"candidate_1","comment_ids":["scope","transition","entities","uncertainty"]}]}
```

Candidate references and clause IDs are checked against that exact request.
Missing/duplicate/new candidates, unknown clauses, prose, numbers or any extra
field (including scores, paths, techniques, status, reason or entities) reject
the whole output. Scope and transition clauses are mandatory. The caller renders
these approved clauses with the original candidate/evidence references and
locally restores aliases. This permits presentation refinement, not novel
free-form security reasoning or new facts.

Successful calls change only `explanation` and `explanation_status=llm_selected`.
Rejected/failed/timed-out calls retain the exact deterministic explanation,
set `explanation_status=deterministic`, and append a redacted issue:
`llm_output_rejected`, `llm_provider_error`, `llm_timeout`,
`llm_privacy_skipped`, `llm_credential_skipped` or `llm_audit_unavailable`. They never alter risk/likelihood,
`numeric_assessment_status`, status, reason, candidate order, selected path,
entities, techniques or abstention. No candidates means no call.

### Deadline and privacy

One monotonic **10-second total budget** covers preparation, attempted-send
logging, spawn, provider import/call, retries and validation. A smaller positive
budget may be configured for tests; budgets above ten seconds are rejected.
At most two attempts share this deadline. SDK retries are disabled. Each call
runs in a spawned child; an uncooperative child is terminated, with cleanup time
reserved inside the budget. No background provider thread continues after timeout.

Only a closed projection is sent: opaque candidate aliases, existing ATT&CK IDs,
prewritten clauses and stable entity aliases. User/host/service/SID/IP identities
are pseudonymized locally; names embedded inside longer strings use longest-first
substring replacement. The mapping is per request, stays in the parent process,
and is never logged/sent. Raw messages, command lines, event IDs, incident IDs,
asset owners, arbitrary metadata, scores and timestamps are never projected.
Unrepresentable identifiers, unresolved entity bindings, alias collisions or a
failed final identity scan skip the call. Restored identities appear only in the
local explanation, as they already do in the local forecast.

Before each attempt, the exact SDK application request (model, max_tokens, system
prompt and user message), its hash and privacy audit are written exclusively to
`private/llm-payloads/<uuid>.json`, or a configured private audit directory. Failure
to log prevents the call. This is an **attempted-send journal**, not evidence the
provider received it; delivery acknowledgements and HTTP authorization headers
are not logged. Provider exception messages and rejected model output are not
logged, since they may contain secrets. `audit_logged_payloads` verifies the
closed request structure, hashes and an optional identity/content denylist.
The journal has no alias mapping or raw endpoint evidence. These private files
are separate from forecast-history retention; preserve/remove them according to
your operator log-retention policy.

Enabled history assessments use a separate explanation-profile identity; the
disabled key algorithm is unchanged (normal agent-version provenance still changes
across releases). Idempotent replay returns the saved result
without another provider call. Use a new evaluation ID for an intentional retry
of a previously persisted deterministic fallback.

### Offline verification and review artifacts

```powershell
python -B -m unittest Prognostic_Agent.tests.test_llm_explanation -v
python -B -m Prognostic_Agent.llm_explanation_demo
```

The fake-provider demo writes disabled/fake JSON, a full unified explanation diff,
a comparison and payload privacy audit under a new `private/phase3-review/` run.
It asserts byte equality of all non-explanation fields, with identical scores,
status/reason, numeric completeness, paths and diagnostics. Nothing is run on
real endpoint events and no external call occurs.

### Clause-selection status and compatibility

`explanation_status=llm_selected` means an LLM selected approved clauses; it does
not mean the model generated their prose. `deterministic` is unchanged. The old
`llm` status is rejected for new forecasts. Historical 0.3.0 records are not
rewritten; their original version/status remains visible when reading history.
Versioned explanation-profile identities prevent silently reusing old selections.

### Alias and credential boundaries

The alias map lives only in the caller's memory. Only the closed pseudonymized
projection enters the child process; the map is never passed to it, journaled,
returned in forecasts, or saved to history. Default object representation contains
no identities, and direct pickle/JSON serialization of the map is rejected.
Restored identifiers in a local explanation are expected and are not a stored
alias-to-identity mapping.

For the optional LLM layer's **agent-managed** request journals, returned errors,
and captured provider output: configured `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`
values are checked before journaling a request, before returning child output and
before returning the rendered explanation. SDK Python logging is disabled in the
isolated child; its native stdout/stderr go to the null device. Exceptions produce
fixed markers, not raw messages. The journal auditor checks the entire journal,
including metadata, against the configured credential values. Synthetic-sentinel
tests exercise provider stdout, stderr, logger output, exceptions and reply bodies;
only a pass/fail result is printed. Disabled mode does not read credentials.

This is a scoped code-and-test confirmation, not a claim about arbitrary caller
code, other programs, OS crash/memory dumps, inherited secrets already present in
unrelated input, or malicious custom provider modules that write files directly.
Injected providers are trusted application code, not a sandbox. No real key is
read back or printed to prove these tests.

### Six-case offline payload review

```powershell
python -B -m Prognostic_Agent.llm_privacy_review
```

This produces complete, partial, abstained, domain-username, embedded-hostname,
and stale-asset-partial forecasts using hand-authored synthetic input. There are
**five payload journals for six forecasts**: abstention has no candidates and must
not call a provider or produce a payload. Every other call uses a fake provider.
The review validates each exact journal and checks forbidden identity/message
strings, hashes, map fields and a hostname substring round trip. It saves a table
and full deterministic/selected forecast pairs under a new private review run.
The embedded-hostname case uses a hostname inside a longer entity string; metadata
with the bare name is never sent. A direct `prefix-host_1-suffix` redaction probe
also verifies substring handling and local round-trip restoration.

### Backend forecast versus standalone forecast: legacy compatibility

There is **no built BI Agent**. BI references elsewhere in historical prose or
diagrams describe an unbuilt component. `backend/agents.py` contains a class named
`BIAgent`, invoked by its legacy pipeline, that calculates compatibility values.
This class is not a separate implemented BI service and is not the integration
target. The earlier BI-primary-consumer proposal is superseded by a direct
Orchestrator proposal. No backend code is changed by Stage 2a.

The backend's existing `PrognosticAgent` writes `incident.forecast`, combining
70% Analyst total risk and 30% IP-reputation risk, with generic risk paths or malware
tactic labels. The current Orchestrator reads it through model features,
`playbooks.incident_risk`, fallback scores and legacy plan reconstruction. Other
readers include database persistence, ingest summaries, dashboard scoring,
playbook explanations, compatibility calculations and ADFA/EMBER benchmarks.
This legacy contract is not the standalone engine's ATT&CK forecast contract.
The standalone score already includes asset impact. It must not be fed into the
legacy score/criticality calculation as if those were interchangeable inputs.

## Direct Orchestrator components ? Stage 2a only

Version `0.4.0a1` supplies independently tested components. **Nothing is wired to
the backend, no backend configuration is changed, and no backend action path has
new guards yet.** This is not a claim that the existing running backend is in dry
run. LLM explanation stays off in this client regardless of backend LLM settings.
Consequence fields, watcher, controlled endpoint tests and audit-policy changes
remain on hold.

Files:

- `schemas/prognostic_forecast_for_orchestrator.v1.schema.json`: closed structural/conditional
  schema; generated artifact is checked against the runtime definition.
- `orchestrator_contract.py`: serializer, structural/cross-field validation,
  identity/freshness checks, and live-use refusal for the v1 shadow-only contract.
- `orchestrator_client.py`: local bounded worker, Analyst adapter, history and
  immutable inventory-byte snapshot; no backend imports or external provider.
- `orchestrator_advisory.py`: approved exact-destination slot permutation only.
- `orchestrator_shadow_log.py`: private decision files and a summary view.

### Contract and null/error handling

The contract identifier is `prognostic_forecast_for_orchestrator.v1`, with
`contract_version=1` and `execution_mode=shadow_only`. It contains persisted
forecast ID/revision, request/alert/Analyst revision and canonical input fingerprint;
response type/status/reason; numeric/explanation status; nullable risk and risk
basis; asset-impact/source flags; selected path and destination; ranking index
(explicitly not probability or severity); probability (always null); separate
observed/reachable scope and counts; horizon/timestamps; heuristic/environment,
issues and rule/weight/config/agent versions.

Forecasts require real persisted history IDs and versions. Abstention has no path,
destination or ranking index; retained risk is impact-only. Errors and benign
skips have null status, risk, forecast IDs, path, index, timestamps/horizon and
unknown scope (null, not an empty known list). There is no null-to-zero coercion.
The receiver may validate the alert, revision, fingerprint and environment, and
must supply its current clock to reject expired/future forecasts. Production
historical-cutoff overrides are refused by the client. Every v1 contract refuses
live use: non-production gives `non_production_forecast`; production gives
`shadow_only_contract`. No backend enforcement is implied until Stage 2b.

### Client usage and benign skip

```python
from pathlib import Path
from Prognostic_Agent.orchestrator_client import OrchestratorClientConfig, OrchestratorForecastClient
from Prognostic_Agent.orchestrator_shadow_log import ShadowDecisionLog

client = OrchestratorForecastClient(OrchestratorClientConfig(
    environment="test",
    inventory_path=Path("Prognostic_Agent/private/RETURNED_INVENTORY/inventory.json"),
))
# incident is a serialized Analyst incident. baseline_options is independently
# evidence/model/policy-qualified; this example does not run an Orchestrator.
review = client.assess_and_log(
    incident, baseline_options,
    shadow_log=ShadowDecisionLog(environment="test"),
)
```

The default client deadline is 3 seconds (configurable up to 30), shared across
preparation and the local worker. Windows uses a dedicated kill-on-close Job
Object; POSIX uses a process group. Worker descendants are terminated on timeout.
The worker waits for stdin until isolation is assigned. Failure to establish
isolation returns no forecast. There are no inline retries. A trusted injected
transport exists for tests and must honor its deadline; the default local
transport enforces cancellation. No endpoint action API exists in these modules.

Analyst `verdict=benign` is checked **before** adapting, opening inventory/history,
spawning or forecasting. It returns `response_type=skipped_benign`,
`reason=skipped_benign`. Use `assess_and_log` to include skips in the shadow log.
Low-level `assess` deliberately does not write a decision log; the caller must
log its returned record. Errors preserve a baseline proposal, never imply low
risk, and do not authorize actions. Logging failure is returned separately as
`shadow_log_unavailable`. Skips never create a forecast-history row.

History defaults to `private/orchestrator/forecast_history.db`, separate from
`soc_agents.db` and the existing daily shadow history. WAL, busy timeout, schema
migrations, retention, evidence-hash defaults and revisions reuse the existing
history implementation. The inventory is read once; its exact bytes are hashed
and immutable parsed records are passed to enrichment. The evaluation identity
includes that hash and cutoff; the same input/context/cutoff replays its history
record. Raw worker diagnostics are suppressed and errors expose fixed codes.

### Approved mapping and independent eligibility

Mapping version: `destination-option-priority.v1`. Its SHA-256 covers the version
and exact mapping and is included in **every** decision record, including skips
and errors.

| Exact destination | Priority in mapped slots | Rationale |
| --- | --- | --- |
| T1003.001 | isolate_endpoint, disable_user | Prioritize already justified host containment and account response |
| T1021.002 | isolate_endpoint | Prioritize containment of the observed host, never the reachable-only host |
| T1078 | disable_user, isolate_endpoint | Prioritize an independently justified account response |

Only complete/partial, valid, unexpired forecasts may inform ordering. All mapped
options must occur exactly once and be independently eligible. Only slots already
occupied by those mapped options are permuted; unmapped options stay at their
**exact indices**. Other destinations, including sub-techniques of a listed parent,
preserve baseline order. A missing/ineligible/ambiguous mapped option preserves
order. No new action, threshold, probability, target or approval change occurs.

Each baseline option is a JSON object. Mapped options require `action`,
`target_entity_id` (a canonical **observed** entity), `eligible=true` and boolean
`approval_required`; explicit false `selected`/policy allowance refuses reordering.
Future backend code must derive eligibility from independent evidence and policy,
not from this forecast. `option_id` is recommended for stable log references.
Other fields, including probabilities, policy details and targets, travel with
the option unchanged. Risk/index/criticality are never used as arithmetic inputs
by the advisory. A supplied risk of 72 remains 72; null remains unknown.

### Decision logs and summary

Records are exclusive per-decision files under `private/orchestrator-shadow/`.
They include forecast ID/revision/type/status/reason, numeric status, before/after
option order, mapping version/hash, reason/limitations codes, `dry_run=true` and
`executed_actions=[]`. Target/incident/option references are hashed for logs;
raw target identities and arbitrary option metadata are not copied into logs.
Unknown eligibility/approval fields remain null. This records a proposal, not
proof that an independent eligible target was compromised.

```powershell
python -B -m Prognostic_Agent.orchestrator_shadow_log --environment test
```

Summary includes status/reason counts, order-change count/rate, skipped/error
decisions and distinct incident counts, forecast counts, mapping versions and
invalid/unreadable log-file counts. Decision counts include repeated reviews;
distinct incident counts deduplicate known incident references. Decisions with no
incident identity are counted as unbound, not invented incidents. An incident can be
skipped in one revision and errored in another, so categories need not be disjoint.
A zero denominator gives a null rate. Empty known lists and unknown scope are
kept separate. No background runner, queue or watcher is installed.

### Stage 2b alternatives ? proposal only

| | Option A: system-wide dry run | Option B: side-channel observer |
| --- | --- | --- |
| Legacy decisions | Compute baseline, suppress Orchestrator effects | Preserve current legacy proposal and execution behavior |
| Standalone result | Compare eligible option orders in dry run | Log forecast and would-be order on a detached snapshot only |
| Side effects | Block tickets, response actions, feedback and online updates | Observer executes nothing; legacy effects can still occur under existing policy/approval |
| Failure | Baseline proposal/log, still no execution | Observer failure cannot alter legacy decisions |
| Backend files | config.py, api.py, agents.py, new prognostic_bridge.py, explain.py, new tests/test_prognostic_shadow.py | config.py, api.py, agents.py (observer hook only), new prognostic_bridge.py, new tests/test_prognostic_shadow.py |
| Main risk | Suppresses existing ticket/response workflows and may delay operational response | Does not provide a system-wide no-execution guarantee; bounded observation adds latency and logs can be unavailable |

**Recommendation: Option B for initial observation**, provided its narrower
safety boundary is explicitly accepted: the forecast never influences a live
plan, while legacy actions remain possible. If nothing anywhere may execute,
choose A instead. B would keep the contract outside live plan/feature fields,
pass a serialized detached snapshot to this client, and swallow observer failures
without changing the legacy response. Its policy/approval, model probabilities,
criticality handling and decision feedback stay untouched. No callbacks or either
mode are implemented in Stage 2a. A later live integration remains separately
approved work, and must reject non-production/shadow contracts at every actuator
entry point. Legacy `incident.forecast` remains intact in both proposals.

### Stage 2a read-only backend test and history report

Measured on 2026-11-24 using the current checkout, with all temporary output under
`private/test-runs/stage2a-backend/`: **63 backend tests**, zero failures/errors,
zero expected failures, **seven unexpected passes**, zero skipped. The known
`GathererTests.test_channel_failure_keeps_other_channels` error did not reproduce
in this invocation. This does not rename/fix the module collision or establish
that every import order is safe. `unittest` treats unexpected passes as a
non-successful suite; the approval decorators were deliberately not changed.
All seven currently decorated approval methods passed unexpectedly. The ordinary
`test_reingestion_preserves_denial_and_decision_audit` passed normally.

The harness used the existing backend test discovery order, disabled bytecode,
set the default database to memory, placed temporary directories inside private/,
redirected `orchestrator_model.FEEDBACK_PATH` privately, and redirected returned
model instances' save paths while preserving original model reads and inference.
Hashes of **all 327 tracked files before and after that isolated test run matched**.
The backend source, decorators and database were not modified. This is a report
of this measured run, not an assertion that the older failure counts still hold.

Backend test write-capable locations inspected:

| Path / output | Cause and containment |
| --- | --- |
| `:memory:`; temporary `approvals.db`, `test.db`, temporary service databases and SQLite journal companions | Incident repository tests; temporary output was confined under private/ |
| Temporary fixture text/XML/log inputs | Collection and ADFA benchmark tests; temp directories cleaned by tests |
| Temporary `report.json`, `predictions.csv` | `benchmark_adfa.run_benchmark`; output is under its temporary directory |
| `Orchestrator_Agent/feedback/decisions.jsonl` by default | `record_feedback`; redirected privately for the measured run |
| Loaded model `.joblib` and sibling `.tmp` by default | `ResponseModel.learn` atomic replacement; model save paths redirected privately |
| `soc_agents.db` relative to process cwd if importing the API without a test override | Potential default initialization; this run forced the default to memory |
| Python `__pycache__/*.pyc` without `-B` | Import side effects; disabled for this run |

After the measured run only the private result JSON and verbose test log remained;
no feedback/model file was produced. The tracked Orchestrator model has no diff
from HEAD and its observed modification time is **2026-11-23 22:12:19 PST**.
There is no complete before/after tracked-file manifest for every historical test
run, so older dirty-file changes cannot responsibly be attributed to tests from
mtime alone. The current isolated run is proven to have changed no tracked file;
that narrower statement is not a retrospective guarantee for every earlier run.

Decorator history (identities redacted): `c5ee804` adds the expected-failure
wrapper on the re-ingestion method. Merge **`71e2632`**, at **2026-11-23 22:11 PST**,
omits it relative to that parent while integrating the neighboring contradictory-
playbook test; the other parent `4b6d8b4` has the undecorated method. Current
`backend/tests/test_approvals.py` has no local diff; its mtime is
**2026-11-23 22:12:19 PST**. These facts support merge integration as the source,
not a later uncommitted edit, and do not prove a particular operator or intent.

## Opt-in backend side-channel observer

The `prognostic-observer` integration is off by default. It leaves the legacy
`incident.forecast`, response plan, approval state and actions unchanged. It
records a separate would-be option order under `private/orchestrator-observer/`;
forecast history is under `private/orchestrator/forecast_history.db`. All v1
advice remains shadow-only, including when its environment is production.
Use `test` for the operator examples below. There is no watcher or scheduled task.

To enable it for a backend started from the same PowerShell environment, set:

```powershell
$env:SOC_PROGNOSTIC_MODE = 'shadow'
$env:SOC_PROGNOSTIC_ENVIRONMENT = 'test'
$env:SOC_PROGNOSTIC_INVENTORY_PATH = "$PWD\Prognostic_Agent\private\inventory-latest.json"
```

Point the inventory setting at an actual imported inventory with the approved
normal overlay before starting. The `inventory-latest.json` publication described
below is proposed, not implemented. Restart the backend to apply settings.
To disable, set `$env:SOC_PROGNOSTIC_MODE = 'off'` and restart. Optional timeout
and queue settings default to three seconds and 64 pending jobs. Mode off does
not construct the observer and returns before snapshotting/copying.

Notification coverage: `OrchestratorAgent.evaluate_and_respond()` notifies after
recording an approval-required decision, or after `_execute_plan()` returns.
The normal pipeline and `SecurityOperationsPipeline.reassess()` reach that
method, including re-triage after an asynchronous Analyst review. Analyst-benign
incidents record a skip without a forecast. **Gap:** `review_response()` does
not notify: human approval/denial of a stored plan has no separate shadow entry.
Neither direct `_execute_plan()` calls nor repeat updates that bypass reassessment
notify. No additional notification hook has been added for these paths.

The worker calls `confine_private_runtime()` in normal runtime, before importing
the engine or a client. Its Python audit hook rejects ordinary file/SQLite writes,
directory creation, removal and rename outside `Prognostic_Agent/private/`, and
blocks socket connections. Read access is allowed; SQLite `:memory:` and the
worker's stdout pipe are allowed. This is a trusted-code guard, not an operating
system sandbox: it does not establish isolation against arbitrary native code,
uncovered syscalls or filesystem races. Worker code must remain trusted. The
real-worker regression test in `backend/tests/test_prognostic_shadow.py` verifies
private file/SQLite success and outside-private file/directory/SQLite rejection.

`GET /orchestrator/status` is read-only. Its observer block is mode-gated and
contains counters, queue depth/capacity, fixed diagnostic codes and metadata;
it contains no incidents, events, targets or forecast content. The whole endpoint
also retains its existing model metadata and thresholds, so the whole response
is not literally counters-only. Counters reset when the backend restarts.

Print a UTC date-range summary (start inclusive, end exclusive):

```powershell
python -B -m Prognostic_Agent.orchestrator_shadow_log --directory Prognostic_Agent/private/orchestrator-observer --environment test --start 2026-11-23T00:00:00Z --end 2026-11-30T00:00:00Z
```

It includes forecast status/reason counts, skips, order changes and errors.
Counts are per decision, with separate distinct-incident counts. Malformed files
whose date cannot be read are reported directory-wide. Queue overflow and
shutdown-drop counters exist only in process memory and cannot be reconstructed
for historical ranges. Without a status snapshot, queue counts are explicitly
unavailable, never invented as zero. Optionally capture a read-only snapshot:

```powershell
Invoke-RestMethod http://localhost:8000/orchestrator/status | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 Prognostic_Agent/private/observer-status.json
python -B -m Prognostic_Agent.orchestrator_shadow_log --directory Prognostic_Agent/private/orchestrator-observer --environment test --start 2026-11-23T00:00:00Z --end 2026-11-30T00:00:00Z --queue-status-file Prognostic_Agent/private/observer-status.json
```

The command whitelists queue metrics from that snapshot and labels their scope
`process_lifetime_not_date_filtered`, separate from the dated decision counts.
Disabled, mismatched-environment or missing snapshots report unavailable counts.
No network request, backend import or write is made by the summary command.

Inventory freshness proposal only: (A) keep versioned export/import/overlay
outputs and manually repoint the observer setting after a successful refresh;
or (B) have the existing daily script publish the validated effective inventory
to `private/inventory-latest.json`. For B, write a temporary sibling then replace
the latest file atomically, retaining the versioned source, hash and collection
timestamp. Failed imports must leave the previous latest file and timestamp
unchanged. Publish provenance with the inventory, not just a filesystem mtime.
The observer already reads inventory per forecast, so successful publication
would not require a worker restart. No publisher or freshness gate is implemented
here. Proposed policy: if the authenticated collection timestamp is missing,
future-dated or older than 24 hours, return an operational no-forecast result
(`asset_inventory_stale` for age), log the issue, and retain the legacy decision.
Do not refresh timestamps without recollection. Per-record `last_updated` checks
remain necessary even for a newly published file. Currently the engine applies
existing record-level freshness rules, which may yield partial/abstained results;
there is no whole-file age refusal. A daily run needs monitoring or an on-demand
manual refresh around its 24-hour boundary; no watcher is proposed for this phase.
