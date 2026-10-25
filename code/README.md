# Ghost Data Still Exists - runnable Phase 6 submission

Python 3.11+ (verified with Python 3.12.10). The deterministic application needs
no model API key, calls no provider, and never reads public expected answers in
production. All evidence stays external to the source archive.

## Setup and full run

Extract code.zip. Keep the organizer dataset/ beside code/, or pass its absolute
path. Install Python and local Poppler pdftotext on PATH for PDF text extraction.
On Windows, existing PowerShell/System.Drawing and Windows.Media.Ocr provide
local PNG decoding/OCR; the bundled ghost_audit/adapters/windows_ocr.ps1 is required.
On non-Windows, install Pillow for PNG decoding; Windows OCR is unavailable and
visual gaps stay explicit. Do not expect byte-identical multimodal results across
different OCR backends. No paid/provider fallback is implemented or required.
Missing/unreadable evidence is recorded explicitly, never treated as absence.

From the extracted/repository root:

```text
python code/main.py run
python code/scripts/validate_output.py --input output.csv
```

This reads dataset/deletion_requests.csv and the participant identity, history,
activity, manifest, policy and evidence files. It writes root output.csv and
code/evaluation/full_run_report.md. Output has exactly518 data rows in lexical
case_id order. The blank dataset/output.csv remains untouched. Default paths
resolve from the project root, independently of current working directory.

Outside that directory, use absolute script/dataset/output/report paths:

```text
python <solution>/code/main.py run --dataset-dir <dataset> --output <destination>/output.csv --report <destination>/run_report.md
python <solution>/code/scripts/validate_output.py --dataset-dir <dataset> --input <destination>/output.csv
```

The validator separately checks exact schema/keys/order/JSON/citation rules and
source availability, then regenerates temporal fact/policy certificates. It
permits conservative INCOMPLETE/[] when the strict investigation is unresolved.
It does not certify semantic completeness. --strict-coverage additionally rejects
unresolved diagnostics and is expected to fail on this dataset checkpoint.

## Semantics and limitations

Explicit non-deletion intent produces NOT_APPLICABLE/[] before per-case state
work. COMPLETE requires the existing positive verification proofs and no current
case blockers. Unknown authorized deletion becomes conservative INCOMPLETE,
with only grounded findings/actions/checks; it can have [] when no action is
supported. This means unverified completion, not proof of a remaining record.
Unresolved intent also stays conservative without authorizing invented actions.
Full-run diagnostics preserve precise strict blockers separately from statuses.
The three-phase requirement is retained for grounded incomplete plans; fallback
rows intentionally do not invent findings or operations merely to fill phases.

Historical identifiers, source/event clocks, physical replicas, claims versus
readbacks, retention and tombstone constraints remain enforced. Unknown scoped
absence, ownership and retention conditions are not guessed. Fifteen visual files
are inspected/extracted with partial semantics; remaining gaps limit accuracy.
The application proposes plans only; it performs no real deletion or remediation.

## Tests and independent public evaluation

```text
python -m unittest discover -s code/tests -v
python code/evaluation/main.py --samples --diagnose-all --submission --measure
python code/main.py audit-diagnostics --measure
python code/main.py identity-coverage
python code/main.py evidence-smoke --measure
python code/main.py state-diagnostics --measure
```

The evaluator runs production before reading sample_output.csv, includes every
public case in the denominator, reports multiset precision/recall/F1, field/index
and exact-array scores, and executes three independent synthetic cases. Omit
--submission to reproduce strict investigative scoring. --reports-dir selects
an alternate directory. Evaluating samples overwrites evaluation Markdown files;
the full-run usage report and production CSV are generated separately.

## Packaging and provenance

```text
python code/scripts/package_submission.py --dry-run
python code/scripts/package_submission.py --build
```

The build keeps code/ (including the local OCR helper), the organizer root
README.md, and mandatory reports both under code/evaluation/ and evaluation/
for the two organizer path conventions. It excludes dataset, caches, virtual
environments, .env/credentials, archives and private traces. Markdown local
machine paths are privacy-redacted in the ZIP copy only. Source Python remains
unchanged; deterministic ZIP timestamps make repeat builds reproducible.
The historical --dry-run lists the earlier flattened plan and writes nothing;
--build uses the current tree layout described here.

Root log.txt is a separate chat-transcript deliverable, not inside code.zip.
The separate agent-trace instructions require quitting/flushing the coding
session before reviewing/copying its raw traces; no live/private trace is
bundled. Never include auth/configuration stores or credentials.

See docs/phase6_implementation.md, docs/progress.md and the measured evaluation/
reports for actual gates, usage and remaining blockers. Structural validity is
separate from semantic accuracy; hidden-dataset accuracy is unknown. No file is
staged, committed or uploaded by these commands.

## Phase 7 candidate and rollback

The Phase6 root output.csv/code.zip are preserved. Phase7 does not achieve the requested exact-sequence recovery (still1/32), so it is not promoted as an accuracy improvement. Immutable baseline copies live outside the archive in release_baselines/phase6/. Actual Phase7 candidate/reproducibility checks are under release_candidates/phase7/.

```text
python code/main.py run --output release_candidates/phase7/output.csv --report code/evaluation/full_run_report.md
python code/scripts/validate_output.py --input release_candidates/phase7/output.csv
python code/evaluation/main.py --samples --diagnose-all --submission --measure
```

Evaluation creates the isolated phase7_mismatch_analyzer.md and three actual phase7_case_traces.md. They cannot feed production inference. Closure covers all known policy resources, including compliant records; unknown resource IDs and policy conditions remain unresolved. See docs/phase7_accuracy_recovery.md and evaluation/phase7_experiments.md. No accuracy result beyond the32 public samples is claimed.

## Phase 8 read-only loss diagnostics

```text
python code/evaluation/phase8_funnel.py --output code/evaluation/phase8_loss_funnel.md
```

This evaluator runs production before loading public labels and reports all518case funnels plus each public missing step. Expected targets never feed inference. Phase8 is diagnostic-only: no production fix was proved safe, exact arrays remain1/32, and the Phase6/7artifacts remain preserved. See docs/phase8_verification.md and evaluation/phase8_experiments.md. PDF raw-text/OCR search does not certify complete visual semantics.

## Phase 9 selected candidate

Prefer the validated release_candidates/phase9/output.csv and code.zip over Phase6for measured recall/F1,subject to its readiness report. Root artifacts remain Phase6rollback. Exact arrays remain1/32;semantic completeness is not certified.

```text
python code/main.py run --output release_candidates/phase9/output.csv --report code/evaluation/full_run_report.md
python code/scripts/validate_output.py --input release_candidates/phase9/output.csv
python code/evaluation/main.py --samples --diagnose-all --submission --measure
```

Default runtime includes the schema-aware delivery-ticket condition;document support extraction experiment remains off. Opt-in experimental runs are separate:

```text
python code/evaluation/phase9_documents.py evaluate --samples --diagnose-all --submission --measure --reports-dir <experiment-reports>
python code/evaluation/phase9_obligations.py --baseline-documents --reports-dir <isolated-reports>
```

The historical C221-obligation measurements predate the selected policy fix;replaying current code can change that inventory. Coutputs are unverified experiment artifacts and are rejected by the official-plan validator. They are not a submission. See docs/phase9_verification.md and measured evaluation/phase9_experiments.md.
