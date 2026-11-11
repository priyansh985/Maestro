# E0 follow-up evidence

`probe_results.jsonl` and `probe_stderr.log` are the outputs of the unchanged
October 24 behavior probe, rerun during E0 development. `probe_run.json` records
the command, Python environment and successful process exit. The 12 probes use
synthetic data and temporary files; exit 0 means collection completed, not that
the behaviors are safe.

`source_hashes_after_probe.json` was collected **after** the probe completed.
It identifies the implementation observed at collection time, but is not a
before/after stability attestation or release evidence. Later E0 changes to the
validation runner have separate verification and may differ from these hashes.

Observed repairs: invalid release bundles deny admission; the policy signer uses
the real bundle interface; duplicated self-supplied signatures fail verification;
the serialized bundle does not contain the synthetic signing secret.

Reproduced open work: unreachable hybrid control plane reported healthy/online;
coding/research defaults failed task verification; effect-before-journal and SDK
mutation retry each produced two effects; fake/negated citation evidence passed;
backup restore returned zero events and accepted tampering; a newly created agent
could execute after tenant containment. These are tracked in E1–E4, with
production startup and release admission unavailable during E0.
