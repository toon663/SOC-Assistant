# Read-only approval-scope review

The method is `backend/tests/test_approvals.py::ApprovalApiTests.test_reingestion_preserves_denial_and_decision_audit`.
It creates a pending incident in setup, denies it via the decision API, resubmits
the same events to `/events`, checks that the decided payload survives, and checks
that another decision is refused. The relevant code is the decision and event
routes in `api.py`, `IncidentRepository.update_pending_incident` and persistence
in `database.py`, and `OrchestratorAgent.review_response`, Sentinel fingerprinting
and pipeline setup in `agents.py`. Pipeline setup also uses the Analyst,
playbook/policy, model and integration modules below. This is a static dependency
review, not an instrumented coverage trace or a claim that every branch in each
module executes.

Observed filesystem modification times, America/Los_Angeles (PST, UTC-08:00):

| File(s) under backend/ | Modified |
| --- | --- |
| tests/test_approvals.py | 2026-11-23 22:12:19 |
| api.py | 2026-11-23 22:37:08 |
| database.py, agents.py | 2026-11-23 22:12:19 |
| models.py, integrations.py | 2026-11-23 22:12:19 |
| orchestrator_model.py, playbooks.py, policy_engine.py | 2026-11-23 22:12:19 |
| anomaly.py | 2026-11-23 22:12:19 |
| analyst.py | 2026-11-23 16:03:52 |
| config.py | 2026-11-21 22:29:43 |

The current test file has no working-tree diff. Commit `c5ee804` adds the decorator
to this method; merge `71e2632` (2026-11-23 22:11 PST) omits it when compared with
that parent, while introducing the neighboring contradictory-playbook test.
The other parent `4b6d8b4` contains the undecorated method. This supports merge
integration as the source of the changed decorator set. Git records different
author labels on the parent branches and a merge author (identities redacted).
Those metadata do not establish who operated the machine, whether an assistant
was involved, or whether omission was intentional. Modification times indicate
filesystem writes/checkouts, not authorship. The later local `api.py` edit removes
the obsolete gatherer import; it does not alter this decorator. No backend files
were edited for this review.
