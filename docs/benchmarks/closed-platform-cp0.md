# Closed-platform CP0 benchmark contracts

CP0 measures closed-platform analysis without storing commercial artifacts in
the repository. It does not implement binary ingestion or bytecode analysis and
does not establish support for any vendor or product version.

## Contracts

The authoritative contracts are strict Pydantic models in
`cairn/src/cairn/benchmarks/contracts.py`. Published JSON Schemas are in
`cairn/src/cairn/benchmarks/schemas/`:

- `closed-platform-gold-v1.schema.json` describes authorization, provenance,
  independently reviewed labels, and sample hashes.
- `audit-run-export-v1.schema.json` is the bounded interchange shape consumed
  by the evaluator.
- `benchmark-result-v1.schema.json` describes deterministic metric output.

Unknown properties, wrong schema versions, malformed hashes, duplicate labels,
and duplicate JSON keys are rejected. Contract files are limited to 8 MiB.

The published schemas provide strict structural validation and the cross-field
conditions expressible in JSON Schema 2020-12. Property-based uniqueness,
reviewer/adjudicator separation, and exact metric arithmetic cannot be fully
expressed by a portable JSON Schema. Each schema lists those checks in
`x-cairn-runtime-invariants`; passing a generic schema validator alone is
therefore only a preflight. Qualification inputs and copied results must also
be loaded through the version-matched Cairn CLI/Pydantic contract, which is the
authoritative validator.

Gold labels use SHA-256 fingerprints rather than proprietary class or method
names. Every conclusion has hashed evidence and an external reference. A private
manifest must use `secret://` artifact/evidence references and `key://`
decryption-key references. The manifest contains neither encrypted nor plaintext
binaries, decompiled text, credentials, or key material. A synthetic manifest
uses only `fixture://` references and must not carry a key reference.

Every manifest also carries `label_status`. Public project-authored fixtures are
`provisional`; a private manifest is rejected unless its labels are
`human-adjudicated`. Benchmark results repeat both `dataset_visibility` and
`label_status`, so those qualifications remain visible when a result is copied
away from its source manifest.

## Metric definitions

Each metric records an integer numerator, integer denominator, and a ratio
rounded to six decimal places. A zero denominator yields `null`, never a
misleading zero score.

| Metric | Numerator | Denominator |
| --- | --- | --- |
| Entrypoint recall | gold entrypoint fingerprints present in the export | gold entrypoints |
| Critical/high recall | detected gold critical/high findings | gold critical/high findings |
| Precision | exported findings matching a gold fingerprint | exported findings |
| Evidence completeness | required evidence kinds present on matched findings | required evidence kinds across all gold findings |
| Dynamic reproduction | dynamically reproducible gold findings reported reproduced | dynamically reproducible gold findings |
| Coverage gap | gold coverage units reported as a gap or omitted | gold coverage units |

An omitted coverage unit is a gap. Extra exported coverage units do not improve
or reduce a score. Missing findings contribute no evidence, so evidence
completeness cannot hide recall failures.

## Running a benchmark

```bash
cairn benchmarks \
  --gold /secure/metadata/gold.json \
  --audit-run /secure/metadata/audit-run.json \
  --output /secure/results/result.json
```

Without `--output`, the command writes only `benchmark-result-v1` JSON to
standard output. Validation errors include the failing field path and input file
name, but never echo field values. The result has no clock-derived fields and
includes canonical hashes of both validated inputs, so identical logical inputs
produce identical bytes.

## Synthetic matrix

`cairn/tests/closed_platform/fixtures/fixture-matrix-v1.json` covers nested JAR,
WAR, EAR, standalone class, JSP, `web.xml`, XML actions, a synthetic platform
request object, SQL API, authorization guard, and tenant guard. The repository
contains only project-authored Java/XML/JSP source material. Tests needing
archives must compile and package them in temporary directories; generated
binaries are not committed.

Archive reproduction requires JDK 21 and invokes `javac --release 17`; the
checked-in hash was verified with `javac 21.0.11`. The builder rejects a
different JDK major instead of silently producing a different CP0 sample hash.

The checked-in baseline triplet is:

- `fixtures/baselines/synthetic-gold-v1.json`: provisional synthetic labels;
- `fixtures/baselines/synthetic-export-v1.json`: a gold-aligned contract test
  export, not output from Cairn's current analyzer;
- `fixtures/baselines/synthetic-result-v1.json`: the deterministic expected
  evaluator output.

Rebuild the class/JAR/WAR/EAR topology, verify every evidence hash, and
recompute the baseline from zero with:

```bash
cd cairn
uv run pytest -q -p no:cacheprovider tests/closed_platform
uv run cairn benchmarks \
  --gold tests/closed_platform/fixtures/baselines/synthetic-gold-v1.json \
  --audit-run tests/closed_platform/fixtures/baselines/synthetic-export-v1.json
```

The synthetic result intentionally scores the gold-aligned interchange fixture,
so its 1.0 values only prove metric and contract reproducibility. They do not
measure the current analyzer and must not appear in product support claims.

## Private-sample release gate

CP0 infrastructure is established, but the real-sample qualification gate is
currently **BLOCKED**. No authorized commercial binary is present in this
repository or registered by this implementation work.

| Required version line | Authorized deployment | Authorized extension | Human gold | Status |
| --- | --- | --- | --- | --- |
| Yonyou NC/UAP line A | missing | missing | missing | blocked |
| Yonyou NC/UAP line B | missing | missing | missing | blocked |
| Yonyou YonBIP line A | missing | missing | missing | blocked |
| Yonyou YonBIP line B | missing | missing | missing | blocked |
| Weaver Ecology line A | missing | missing | missing | blocked |
| Weaver Ecology line B | missing | missing | missing | blocked |

For each line, onboarding requires a content hash, acquisition and custody
records, explicit rights for static analysis/decompilation/execution, encrypted
`secret://` storage with an external `key://` reference, two independent human
annotations, and separate adjudication. Unknown internet downloads are not an
acceptable substitute.

Real private baselines remain blocked until legally authorized samples are
registered with two independent reviewer records and a separate adjudicator.
Synthetic scores must be labelled "synthetic fixture validation" and cannot be
used to claim vendor support.
