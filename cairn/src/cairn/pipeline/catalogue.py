"""Deterministic remediation and OWASP mapping for promoted Findings.

``Finding.remediation`` is NOT NULL and ``Finding.cwe_id`` is mandatory, but a
candidate carries neither: the Semantic Reviewer produces
``recommended_verification`` (how to settle the question), not
``remediation`` (how to fix it), and scanners produce neither.

Both tables here are code constants. That is the point: a remediation
paragraph reaching a security reviewer should be a statement the platform
stands behind, reproducible across runs and reviewable in a diff — not text a
model generated once and nobody can re-derive. The trade is breadth for
trustworthiness, and a human reviewer can always refine a specific case.

Keyed on CWE rather than on category, because ``category`` is open vocabulary
— :func:`cairn.analysis.normalizers._category` slugifies whatever a scanner
emitted — while CWE is closed and is the field the Finding contract actually
requires.
"""

from __future__ import annotations

# CWE -> OWASP Top 10 2021 category. Only mappings the OWASP 2021 CWE lists
# actually make; a CWE outside this table yields no OWASP category rather than
# a guess, and `Finding.owasp_category` is nullable for exactly that reason.
OWASP_BY_CWE: dict[str, str] = {
    "CWE-16": "A05:2021 Security Misconfiguration",
    "CWE-22": "A01:2021 Broken Access Control",
    "CWE-77": "A03:2021 Injection",
    "CWE-78": "A03:2021 Injection",
    "CWE-79": "A03:2021 Injection",
    "CWE-89": "A03:2021 Injection",
    "CWE-90": "A03:2021 Injection",
    "CWE-91": "A03:2021 Injection",
    "CWE-94": "A03:2021 Injection",
    "CWE-200": "A01:2021 Broken Access Control",
    "CWE-209": "A05:2021 Security Misconfiguration",
    "CWE-284": "A01:2021 Broken Access Control",
    "CWE-285": "A01:2021 Broken Access Control",
    "CWE-287": "A07:2021 Identification and Authentication Failures",
    "CWE-306": "A07:2021 Identification and Authentication Failures",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-328": "A02:2021 Cryptographic Failures",
    "CWE-330": "A02:2021 Cryptographic Failures",
    "CWE-352": "A01:2021 Broken Access Control",
    "CWE-362": "A04:2021 Insecure Design",
    "CWE-400": "A04:2021 Insecure Design",
    "CWE-434": "A04:2021 Insecure Design",
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    "CWE-522": "A07:2021 Identification and Authentication Failures",
    "CWE-601": "A01:2021 Broken Access Control",
    "CWE-611": "A05:2021 Security Misconfiguration",
    "CWE-639": "A01:2021 Broken Access Control",
    "CWE-798": "A07:2021 Identification and Authentication Failures",
    "CWE-829": "A08:2021 Software and Data Integrity Failures",
    "CWE-863": "A01:2021 Broken Access Control",
    "CWE-915": "A08:2021 Software and Data Integrity Failures",
    "CWE-917": "A03:2021 Injection",
    "CWE-918": "A10:2021 Server-Side Request Forgery",
    "CWE-1104": "A06:2021 Vulnerable and Outdated Components",
}

# Java- and Spring-specific where that adds something a reader could act on.
REMEDIATION_BY_CWE: dict[str, str] = {
    "CWE-16": (
        "Correct the framework configuration rather than adding a compensating "
        "check at the call site. Review the effective Spring Security filter "
        "chain, servlet and actuator exposure, CORS origins and error-page "
        "settings for this module, and pin the intended values in configuration "
        "that ships with the build rather than in an environment-specific "
        "override."
    ),
    "CWE-22": (
        "Do not build filesystem paths from request input. Resolve the "
        "user-supplied name against a fixed base directory, canonicalise with "
        "`Path.normalize().toRealPath()`, and reject anything whose resolved "
        "path does not start with that base. Prefer mapping an opaque "
        "identifier to a server-side path over accepting a path at all."
    ),
    "CWE-77": (
        "Do not assemble a shell command from request input. Use "
        "`ProcessBuilder` with an argument list so no shell parses the string, "
        "and validate each argument against an allowlist. If a shell is truly "
        "required, the argument must come from a fixed set of constants."
    ),
    "CWE-78": (
        "Do not assemble a shell command from request input. Use "
        "`ProcessBuilder` with an argument list so no shell parses the string, "
        "and validate each argument against an allowlist. If a shell is truly "
        "required, the argument must come from a fixed set of constants."
    ),
    "CWE-79": (
        "Encode on output for the context the value lands in — HTML body, "
        "attribute, JavaScript or URL — rather than sanitising on input. In "
        "Thymeleaf prefer `th:text` over `th:utext`; where markup genuinely "
        "must be rendered, pass it through a configured sanitiser allowlist."
    ),
    "CWE-89": (
        "Use a parameterised query so the value never reaches the SQL parser as "
        "syntax: a `PreparedStatement` placeholder, a JPA named parameter, or "
        "MyBatis `#{}`. MyBatis `${}` performs textual substitution and is not a "
        "parameter. Where an identifier such as a column or sort direction must "
        "vary, map the request value through a server-side allowlist rather than "
        "concatenating it."
    ),
    "CWE-90": (
        "Escape LDAP distinguished names and filters with the framework's own "
        "encoder — Spring LDAP's `LdapEncoder`, or `javax.naming` filter "
        "arguments — rather than concatenating request values into a filter "
        "string."
    ),
    "CWE-91": (
        "Build XML with a document API rather than string concatenation, so "
        "request values become text nodes instead of markup."
    ),
    "CWE-94": (
        "Remove the dynamic evaluation. Where behaviour must vary at runtime, "
        "dispatch through a fixed map of server-side implementations keyed by a "
        "validated identifier instead of evaluating a supplied expression or "
        "script."
    ),
    "CWE-200": (
        "Return only the fields the caller is entitled to. Project the response "
        "through an explicit DTO rather than serialising the persistence entity, "
        "and scope every read query by the authenticated principal's tenant, "
        "organisation or owner."
    ),
    "CWE-209": (
        "Return an opaque error to the caller and keep the stack trace, SQL "
        "text and internal identifiers in the server log. Set an explicit error "
        "handler so the framework's default whitelabel or debug page cannot "
        "reach a production response."
    ),
    "CWE-284": (
        "Enforce the access decision on the server for every entry point, not "
        "only on the ones the UI links to. Prefer a deny-by-default filter chain "
        "with explicit allow rules over per-handler annotations, so a newly "
        "added endpoint is protected before anyone remembers to annotate it."
    ),
    "CWE-285": (
        "Check that the authenticated principal is entitled to the specific "
        "object, not merely authenticated. Push the ownership predicate into the "
        "query — filter by tenant or owner in the `WHERE` clause — so a missing "
        "check cannot return another principal's row."
    ),
    "CWE-287": (
        "Route the credential check through the framework's authentication "
        "provider rather than comparing values in a handler, so lockout, "
        "credential encoding and session fixation protection all apply. Ensure "
        "the session identifier is regenerated on successful login."
    ),
    "CWE-306": (
        "Add the endpoint to the authenticated section of the security "
        "configuration. Where an endpoint must stay anonymous, state that "
        "intent explicitly in the filter chain rather than leaving it "
        "unmatched, so the exemption is visible in review."
    ),
    "CWE-327": (
        "Replace the algorithm with a current one: AES-GCM for symmetric "
        "encryption, SHA-256 or better for digests, and a memory-hard function "
        "(bcrypt, scrypt, Argon2) for passwords. Never reuse an IV or nonce with "
        "one key."
    ),
    "CWE-328": (
        "Stop using this digest for a security decision. Use SHA-256 or better "
        "for integrity, and a memory-hard password hash (bcrypt, scrypt, "
        "Argon2) with a per-credential salt for passwords."
    ),
    "CWE-330": (
        "Use `java.security.SecureRandom` for any value an attacker must not be "
        "able to predict — tokens, session identifiers, password resets, nonces. "
        "`java.util.Random` and `Math.random()` are reproducible from observed "
        "output."
    ),
    "CWE-352": (
        "Leave CSRF protection enabled for cookie-authenticated, state-changing "
        "requests. Where the endpoint is genuinely stateless and "
        "token-authenticated from a non-browser client, record that in the "
        "security configuration as a narrow exemption rather than disabling the "
        "protection globally."
    ),
    "CWE-362": (
        "Make the check and the state change atomic. Push the invariant into the "
        "database — a conditional `UPDATE ... WHERE`, a unique constraint, or a "
        "`SELECT ... FOR UPDATE` inside the transaction — rather than relying on "
        "a read followed by a write. A `@Transactional` boundary alone does not "
        "serialise concurrent callers at the default isolation level."
    ),
    "CWE-400": (
        "Bound the work a single request can cause: cap page size, request body "
        "size, and result-set size, and set explicit timeouts on outbound calls "
        "and queries so one caller cannot hold resources indefinitely."
    ),
    "CWE-434": (
        "Validate the upload by content rather than by the client-supplied name "
        "or content type, store it outside the web root under a generated name, "
        "and never serve it from a path that any handler can execute or "
        "interpret."
    ),
    "CWE-502": (
        "Do not deserialise attacker-controlled bytes into arbitrary types. Use "
        "a data format with no type resolution (plain JSON to a fixed DTO), and "
        "if a polymorphic mapper is unavoidable, restrict it to an explicit "
        "allowlist of permitted classes rather than a package prefix."
    ),
    "CWE-522": (
        "Remove the credential from the code and configuration that ships with "
        "the build, load it from the deployment's secret store at runtime, and "
        "rotate the exposed value — a credential in version control must be "
        "treated as disclosed regardless of repository visibility."
    ),
    "CWE-601": (
        "Do not redirect to a location taken from the request. Redirect to a "
        "server-side path selected by a validated key, or match the supplied "
        "target against an allowlist of absolute URLs before use."
    ),
    "CWE-611": (
        "Disable external entity and DTD processing on the parser factory "
        "before use: set `disallow-doctype-decl` to true, and "
        "`external-general-entities` and `external-parameter-entities` to false. "
        "Every factory instance needs this — the defaults are unsafe, and a "
        "hardened factory in one class does not protect another."
    ),
    "CWE-639": (
        "Scope the lookup by the authenticated principal instead of trusting the "
        "identifier in the request. Filtering by owner in the query is what makes "
        "the check unforgettable; a separate ownership assertion after the read "
        "can be skipped on a later code path."
    ),
    "CWE-798": (
        "Remove the hardcoded credential, load it from the deployment's secret "
        "store, and rotate the exposed value. Add the pattern to the secret scan "
        "so a reintroduction fails the build rather than waiting for the next "
        "audit."
    ),
    "CWE-829": (
        "Resolve dependencies only from the configured internal mirror, pin "
        "versions and verify checksums or signatures, so the build cannot pick "
        "up a substituted artifact."
    ),
    "CWE-863": (
        "Correct the authorization predicate rather than adding a second check "
        "beside it. Verify what the rule covers in the framework's own terms — "
        "which paths a matcher actually matches, whether the proxy applies the "
        "annotation on this call path — and cover the corrected rule with a test "
        "that fails without it."
    ),
    "CWE-915": (
        "Bind request bodies to an explicit DTO holding only the fields a caller "
        "may set, and map to the persistence entity server-side. Binding "
        "directly to an entity lets a caller set any writable field it declares."
    ),
    "CWE-917": (
        "Do not evaluate an expression built from request input. Where "
        "SpEL or OGNL evaluation is required, parse with a restricted evaluation "
        "context that exposes no type references, and supply the user value as a "
        "variable rather than as expression text."
    ),
    "CWE-918": (
        "Do not fetch a URL taken from the request. Where an outbound call must "
        "vary, resolve the target through a server-side allowlist of hosts, "
        "re-validate after DNS resolution to reject link-local, loopback and "
        "cloud-metadata addresses, and disable redirect following so a permitted "
        "host cannot forward the request elsewhere."
    ),
    "CWE-1104": (
        "Upgrade the component to a supported release, or replace it. Record the "
        "decision and the next review date where a fixed version does not yet "
        "exist, so the exposure stays visible instead of ageing silently."
    ),
}

# Fallbacks for audit categories whose candidates may carry a CWE outside the
# table above. Keyed on the closed category vocabulary the semantic planner
# assigns (`cairn.orchestrator.semantic_tasks`).
REMEDIATION_BY_CATEGORY: dict[str, str] = {
    "authorization": REMEDIATION_BY_CWE["CWE-285"],
    "command-execution": REMEDIATION_BY_CWE["CWE-78"],
    "expression-injection": REMEDIATION_BY_CWE["CWE-917"],
    "path-traversal": REMEDIATION_BY_CWE["CWE-22"],
    "spring-security-misconfiguration": REMEDIATION_BY_CWE["CWE-16"],
    "sql-injection": REMEDIATION_BY_CWE["CWE-89"],
    "ssrf": REMEDIATION_BY_CWE["CWE-918"],
    "template-injection": REMEDIATION_BY_CWE["CWE-94"],
    "unsafe-deserialization": REMEDIATION_BY_CWE["CWE-502"],
    "xxe": REMEDIATION_BY_CWE["CWE-611"],
}

GENERIC_REMEDIATION = (
    "Cairn has no specific remediation on file for this weakness class. Treat "
    "the call chain and controllability statement on this Finding as the "
    "starting point: break the path from the external input to the sink, and "
    "cover the fix with a test that fails without it. A reviewer should replace "
    "this text with the concrete change once the fix is decided."
)


def owasp_for(cwe_id: str) -> str | None:
    """The OWASP Top 10 2021 category for a CWE, or ``None`` when unmapped."""

    return OWASP_BY_CWE.get(cwe_id.strip().upper())


def remediation_for(cwe_id: str, category: str) -> str:
    """Remediation text for a promoted Finding.

    Falls back CWE -> category -> generic. The generic text says plainly that
    no specific guidance exists rather than inventing some, so a reader can
    tell the difference between advice the platform stands behind and a gap.
    """

    by_cwe = REMEDIATION_BY_CWE.get(cwe_id.strip().upper())
    if by_cwe is not None:
        return by_cwe
    by_category = REMEDIATION_BY_CATEGORY.get(category.strip().lower())
    if by_category is not None:
        return by_category
    return GENERIC_REMEDIATION
