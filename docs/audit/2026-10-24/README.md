# Evidence index — 24 October 2026

Baseline source: `fb1425235417879e1af227e691a3676ccedd68c0` (`development`).
This audit adds documents and an evidence probe; it makes no product-source changes.
Read the [analysis](../2026-10-24-development-analysis.md),
[roadmap and feature design](../../superpowers/specs/2026-10-24-maestro-next-stage-design.md),
and [first implementation plan](../../superpowers/plans/2026-10-24-maestro-verification-baseline.md).

## Fresh verification

| Command | Result | Scope |
|---|---|---|
| `.venv\Scripts\python.exe -m pytest -q` | Exit 0; **636 passed in 1408.14s** | Existing configured tests directory, including offline adversarial/API/SDK cases |
| `.venv\Scripts\python.exe -m ruff check src tests --output-format concise` | Exit 0; all checks passed | Source and existing tests |
| `.venv\Scripts\python.exe -m mypy src` | Exit 1; **41 errors in 8 files**, 107 source files checked | Current type/interface baseline; failures not suppressed |
| `.venv\Scripts\python.exe -u docs/audit/2026-10-24/probe_development_state.py` | See `probe_run.json` and raw JSONL | Harmless synthetic local counterexamples, not production readiness |
| `.venv\Scripts\python.exe -m ruff check docs/audit/2026-10-24/probe_development_state.py` | Exit 0; all checks passed | New audit helper |
| `git diff --check` | Exit 0 | Tracked diff whitespace check; new documents additionally inspected for broken fences and local links |

The earlier `full_suite3.out` contains a different, historical 636-pass run.
Fresh check summaries are in `verification_results.json`; the check processes'
outputs were read through the execution tool. The JSON contains summary and
final-output excerpts, not a fabricated copy of their full output streams.

## Probe results

`probe_results.jsonl` preserves stdout and `probe_stderr.log` preserves stderr.
`probe_run.json` records the final helper hash and exit status. Results describe
current defects; an `accepted=true` or `verified=true` in a counterexample is an
unexpected product behavior, not an audit pass. `probe_results_initial.jsonl`
preserves the first shorter collection, before backup/retry/containment probes
were added. Use the final collection for the complete evidence set.

| Probe | Reproduced behavior |
|---|---|
| Invalid deployment gate | Invalid/expired/mismatched bundle with impossible threshold returns passed |
| Policy signer | Missing `PolicyBundle.content_hash` raises AttributeError |
| Duplicate self-supplied signatures | Repeated signer accepted; HMAC secret included in serialization |
| Unreachable control plane | Reports healthy/ONLINE without a real health request |
| Coding default loop | `code_read` denied by network mitigation verifier |
| Research default loop | `research_search` denied by network mitigation verifier |
| Sandbox timeout | Wait extends past nominal timeout; elapsed depends on host load |
| Effect-before-journal crash | Same operation executes synthetic effect twice |
| Citation negation/fake marker | Contradiction and nonexistent citation accepted by lexical heuristic |
| Backup restore/integrity | One original event restores zero; altered backup is verified |
| SDK mutating retry | Mock server observes two effects after an ambiguous response |
| Tenant containment | New agent created and allowed while tenant isolation flag remains set |

No real provider calls, Git pushes/PRs, external packet replay, credential
changes, tenant data, database migrations or live server mutations are performed
by this script. It uses local factories/TestClient, mock HTTP transport,
synthetic keys and temporary directories. Do not expose a deployed service for
these probes; the script does not need one.

## Snapshot and limits

`source_hashes.json` records SHA-256 hashes for **182** current source, test,
configuration, packaging and CI inputs. The post-verification comparison is
recorded in `verification_results.json`. Git HEAD alone would not identify
uncommitted source changes, so the content hashes are retained as well.

No real Postgres, OIDC provider, Temporal service, Docker/gVisor environment,
cloud LLM, browser acceptance, useful-task benchmark or customer pilot was run.
No claim of production security, empirical attack resistance, RPO/RTO or market
demand follows from the offline suite. The independent builder check concerned
planning clarity for M0 only, and returned “nothing important left”; it was not a
security review or verification of later roadmap milestones.
