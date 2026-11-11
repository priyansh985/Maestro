# Offline verification

Install a supported Python 3.12 or 3.13 environment with the `dev` extra, then run:

```text
python -m maestro.scripts.validate_v1 --profile offline
```

`maestro-v1-validate` is the editable-install entry point. Validation requires a
source checkout; an installed wheel supports `--help` but cannot validate its
site-packages directory as a repository. Optional arguments are
`--output-dir PATH` and `--timeout-seconds 1800` (per check). Use a new output
directory for each run; existing evidence is not overwritten.

The command runs threat validation, Ruff, mypy, the complete configured tests
directory, and the actual CLI help/version commands once. It continues collecting
results after a failed check. Timeouts/errors fail the overall result. stdout
and stderr are retained separately as UTF-8 logs; `manifest.json` contains their
hashes, source/config/test/packaging input hashes, check outcomes, runtime and
installed distribution versions. A changing input snapshot cannot pass.

Exit 0 means the offline checks passed on a stable input snapshot. Exit 1 means
failure/error/timeout or changing inputs. Invalid arguments or reused output
directories exit 2. Git metadata can be unavailable outside a checkout and is
recorded explicitly. The input content hashes still identify what was checked.

Production readiness is always **not assessed** by this command. OIDC provider,
Postgres RLS, OS sandbox, Temporal, hybrid network, cloud models, real vertical
adapters and browser acceptance remain eight separately named unrun integrations.
Offline fixture tests do not promote those profiles to supported deployments.
Deterministic reproduction is a separate command; live packet replay is not
part of offline validation.

On Windows, each check starts suspended and joins an unnamed job before it can
execute. Cleanup terminates the job and checks that it is empty, including when
the root already exited. Ownership setup failure rejects the check before resume.
This supervises ordinary subprocess descendants, rather than establishing a
security sandbox; see [Microsoft's job-object semantics](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).
POSIX checks run in separate process groups. Cleanup failures are explicit failed
check records and do not turn into release approval.

`ReleaseGateEvaluator.evaluate()` denies admission until a real evidence/trust
verifier is supplied in a later stage. Its explicit `simulate()` method can
display hypothetical gate results, but both admission properties remain false.
No simulation result is valid release evidence. The production API startup
profile is also intentionally unavailable during E0.

Build artifacts with `uv build --no-sources`, then install the wheel into a fresh
environment and run `scripts/wheel_smoke.py` from outside the checkout. That smoke
checks package origin, version, canonical defaults, threats, connector registry,
dashboard HTML and app construction. CI supplies a synthetic test signing key.

The container build requires `--build-arg PYTHON_IMAGE=python@sha256:...` with an
actual Python 3.13 image digest. There is deliberately no floating default.
The runtime installs the built wheel, contains no development extra and runs as
UID 10001 in the research profile. Production startup is unavailable. A Dockerfile
or CI definition is not evidence that the image was built or exercised.
