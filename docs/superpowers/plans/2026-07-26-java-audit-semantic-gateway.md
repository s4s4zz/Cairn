# Java Audit LLM Gateway and Semantic Output Contract

**Status:** Implemented

**Date:** 2026-07-26

**Goal:** Deliver increment 5a of subproject five from the approved Java audit
platform design: the LLM Gateway service, short-lived model grants, the
read-only Tool Broker, the fixed Java audit prompt, the strict semantic output
contract, and the `CandidateFinding` extension that carries semantic evidence
through candidate merging.

## Delivery boundary

This increment supplies the semantic-review substrate and its trust boundary.
It does **not**:

- create semantic AuditTasks or split work by module × attack surface ×
  category;
- advance an AuditRun out of `semantic_auditing`;
- add a `semantic` Sandbox template or image;
- send a single request to a real model endpoint;
- create `Finding` rows, or promote any candidate to a confirmed state;
- mint grants anywhere — there is no minting call site in the tree yet, only
  the `mint_grant` primitive and the Gateway that verifies its output.

Those belong to increment 5b. Everything here is verified end to end against
stub transports, so landing it requires no image build and no network egress.

The Orchestrator still parks a run at `AuditRunStatus.SEMANTIC_AUDITING`
(`cairn/src/cairn/orchestrator/engine.py`), unchanged by this increment.

## Why the Gateway is a service

The semantic reviewer runs inside a Sandbox container on `cairn-analysis-net`
(design spec §5 "AI 只读分析环境", §9.4). A container can only reach an HTTP
endpoint, so the Gateway cannot be an in-process module. It is a
policy-enforcing reverse proxy in front of the upstream Messages API:

```text
GET  /health/live
GET  /health/ready
POST /v1/messages
```

The worker constructs its SDK client with `base_url` pointed at the Gateway and
`api_key` set to its **grant token**. The Gateway verifies the grant, enforces
the model allowlist and budget, substitutes the real key at egress, and returns
the upstream body verbatim. It forwards with `requests` rather than
round-tripping through the model SDK, so unknown request *and* response fields
survive the hop.

The Gateway holds the platform's only long-term model credential. It attaches
to `cairn-analysis-net` (internal) and `cairn-llm-egress` (not internal), and
to **neither** `cairn-control` nor `cairn-sandbox-api`: it needs neither
PostgreSQL nor the Artifact Store, so a compromised Gateway cannot reach the
database. The per-run ceiling travels inside the signed grant, which is what
lets the Gateway enforce a budget with no control-plane reachability at all.

## Grants

An HMAC-SHA256 MAC over the canonical JSON of
`{audit_run_id, task_id, worker, model, expires_at, max_requests,
max_output_tokens}`, encoded `base64url(payload).base64url(mac)`. Verification
compares the MAC with `hmac.compare_digest` **before** parsing the payload, and
rejects non-canonical base64 spellings so one grant cannot occupy two budget
counters. Budget counters key off a domain-separated hash of the decoded MAC, so
credential material never becomes a dictionary key.

The Gateway caps the remaining lifetime it will honour
(`max_grant_lifetime_seconds`, default one hour). §9.5 asks for a short-lived
token, and the verifier is the trust boundary — a misconfigured minter must not
be able to issue a multi-year bearer capability.

Error codes, each pinned to a status: `LLM_GRANT_INVALID` (401),
`LLM_GRANT_EXPIRED` (401), `LLM_MODEL_NOT_ALLOWED` (403),
`LLM_TOOL_NOT_ALLOWED` (403), `LLM_REQUEST_TOO_LARGE` (413),
`LLM_REQUEST_INVALID` (422), `LLM_BUDGET_EXHAUSTED` (429),
`LLM_UPSTREAM_UNAVAILABLE` (502), `LLM_CIRCUIT_OPEN` (503),
`LLM_UPSTREAM_TIMEOUT` (504).

## Two channels

§9.6 requires system instructions and source content to travel separately.
In code that is:

- `JAVA_AUDIT_SYSTEM_PROMPT` — a module constant interpolating **nothing**, so
  the cached prefix stays byte-stable across every scope.
- The per-task scope assignment — a mid-conversation `{"role": "system"}`
  message at `messages[1]`. It must follow a user message and cannot be
  `messages[0]`; both halves of that placement rule are asserted in code,
  because a misplaced system message does not fail loudly at the API, it just
  silently relocates platform directives next to a forgeable channel.
- Repository bytes — only ever inside `tool_result` blocks.

The scope assignment is deliberately **not** repeated on the user channel.
Showing the model a scope assignment there would teach it that assignments
legitimately arrive on the one channel repository content can imitate.

Scope text is itself repository-derived: `ReviewScope.module` traces back to a
`<artifactId>` in a `pom.xml`. It is flattened to a single line before
rendering, so a crafted module name cannot open its own markdown block on the
operator channel.

## Output contract

`SemanticFinding` requires every §7.5 evidence element: locations (at least one
`sink`), an entrypoint-to-sink `call_chain`, `controllability`,
`existing_defenses`, `attack_preconditions`, `impact`, and
`recommended_verification`.

`parse_findings` is the §13.5 acceptance gate, and it is the *only* real gate:
the Messages API strips `minItems`/`minLength` from `output_config.format`, so
the JSON Schema shapes output but cannot constrain it. Each item is validated
independently — one malformed item costs exactly one item.

Because model output is untrusted, it is resolved through `SourceCatalog` in a
new **strict mode** that turns off the leniencies built for scanner output:

| Leniency | Fine for a scanner | Bypass for a model |
|---|---|---|
| Missing line number defaults to 1 | sloppy SARIF | "no code location" becomes a location |
| Bare basename suffix-matches a path | scanners emit basenames | claims a location in a file never opened |
| `int()` coercion | `"15"` from JSON | `true` becomes line 1 |
| Ceiling of EOF + 2 | off-by-one tolerance | anchors a candidate to a line that does not exist |

Cardinality alone does not express "entrypoint-to-sink chain" either: the chain
must begin at an `entrypoint`, end at a `sink`, contain two distinct steps, and
terminate in a path the finding declares as a sink location. Two identical
propagation steps satisfy `len >= 2` while describing no path at all.

Blankness is judged by what renders, not by `str.strip`: U+200B is not
whitespace, so a controllability statement made of zero-width characters would
otherwise satisfy `min_length=1` and display as empty.

Confidence is drawn from `CandidateConfidence` (`high`/`medium`/`low`), which
has no `confirmed` member. The type system, not a runtime check, is what
prevents the model from self-confirming a Finding.

## Candidate merging

`CandidateFinding` gains `call_chain`, `controllability`, `existing_defenses`,
`attack_preconditions`, `impact`, `recommended_verification` and
`severity_conflict`, all optional, so the seven existing scanner adapters
validate unchanged.

`merge_candidates` builds its result as a fresh dict with a fixed key set, so
any field not explicitly merged is silently dropped. Extending the contract
without extending the merge would have destroyed a semantic candidate's call
chain the moment a scanner hit the same `root_cause_key`. The merge keeps the
longest chain, unions defenses, prefers the first non-empty prose value in the
existing ordering, and is order-independent, idempotent, and stable under
re-merge — the Orchestrator re-merges an already-merged payload on every
subsequent tool.

Severity conflicts are recorded rather than resolved. §7.6 wants a disagreement
routed to verification instead of silently adopting the highest severity;
`severity_conflict` captures the distinct claims so 5b can act on it.

Fingerprinting needed no change: `candidate_identity` is tool-agnostic, so a
semantic candidate merges with scanner candidates for free and its fingerprint
is stable for a given `snapshot_sha256`.

## Two pre-existing defects fixed

Both reproduced on `983bbe1` before this increment and were found by the
acceptance review:

- `normalize_cwe_ids` ordered CWE ids numerically while `CandidateFinding`
  required plain-string order, so **any** candidate carrying both a two-digit
  and a three-digit CWE failed contract validation outright — `CWE-89` with
  `CWE-611` was unrepresentable. Numeric order is now canonical end to end;
  changing the normaliser instead would have moved every existing fingerprint.
- The location sort key in `merge_candidates` omitted columns that its dedup
  key included, so two members reporting one line at different column precision
  emitted in member order and `merge([a,b]) != merge([b,a])`.

## Verification

Full suite against a disposable PostgreSQL 16: **521 passed, 5 skipped**
(baseline before this increment: 220 passed, 5 skipped; the five skips are the
opt-in Docker template matrix). `docker compose config --quiet` passes.

The acceptance criteria of §13.5 were checked by adversarial review that
executed its probes rather than reading for intent. It found eleven defects
across two criteria plus five more on a third; all are fixed and each now has a
regression test:

- **AI cannot confirm a Finding** — held on first review, no defects.
- **Incomplete output is rejected** — six bypasses, every one of which turned
  absent evidence into an accepted candidate. Closed by strict-mode resolution,
  chain-shape enforcement, and render-based blankness.
- **Repository instruction files cannot alter platform tasks** — a
  repository-controlled `<artifactId>` could write arbitrary markdown onto the
  `role: "system"` operator channel; the scope assignment was also duplicated
  onto the user channel; an id-less `tool_use` left an unanswerable block in
  history that would cost the whole scope on the next turn.
- **No long-term credentials, no open internet** — the most serious findings in
  the increment:
  - the Gateway forwarded `tools`, `mcp_servers` and `container` verbatim, so a
    worker could declare Anthropic's server-side `web_search`/`web_fetch` tools
    and reach the open internet **from Anthropic's infrastructure**, without a
    packet leaving `internal: true`. Only custom tools now pass.
  - the egress leg followed redirects. `requests` strips `Authorization` across
    hosts but not a custom `x-api-key`, so a 307 re-POSTed the prompt and the
    long-term key to the redirect target, and the Gateway returned that host's
    body to the grant holder. Verified closed against two local servers: the
    attacker host now receives nothing.
  - `http://` was accepted for the upstream origin, putting the long-term key
    in cleartext on the non-internal egress network. HTTPS is now required
    outside loopback.
  - the output-token ceiling was advisory under concurrency; it is now reserved
    under the lock and reconciled on completion. Eight concurrent requests
    against a 1000-token grant now authorize 1000 tokens in total, not 8000.
  - the whole request body was buffered before the size cap and before any
    credential check, so an unauthenticated peer could exhaust the memory of
    the only process holding the model key. Reading is now bounded as it
    streams.

Remaining known gap, unchanged from subproject three: the rootless-daemon path
is still unverified end to end on this host, which lacks `newuidmap`.
