# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in modelgate, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

Email: daniel.amaya.buitrago@outlook.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 72 hours.

## Supported Versions

| Version | Supported |
|---|---|
| 0.x (current) | Yes |

## Security Design Principles

1. **Defense in depth** — multiple layers of checks (proxy, policy, output scanning)
2. **Deny by default** — blocked patterns, PII detection, and injection checks are opt-in but recommended as default-on
3. **Least privilege** — pods run as non-root, drop all capabilities, read-only filesystem where possible
4. **Audit everything** — every request that reaches this middleware emits an audit event. The event's `action` field distinguishes `"allowed"` (all configured checks ran and none fired), `"blocked"` (a check fired and the request never reached upstream), and `"passthrough"` (the middleware could not inspect the request — a non-POST verb, an unparseable body, or a body that didn't match the OpenAI chat schema — but the request DID reach upstream). The compliance floor is "no request ever reaches the upstream without an audit event, and if the audit event doesn't say `blocked` then the request reached the model." <!-- audit-action-values: allowed blocked passthrough -->

5. **Fail modes are explicit in the audit trail, not default-closed** — regex checks (prompt injection, PII, blocked patterns) fail closed. NeMo Guardrails defaults to fail-**open** so a NeMo outage doesn't take the proxy down; policies can opt into fail-closed with `guardrails_fail_closed: true`. When the fail-open branch fires, the audit event's `reason` records `guardrails unavailable (allowed by fail-open policy)` so the trail distinguishes a clean pass from a pass-during-outage — an operator asking "did guardrails inspect this prompt?" can answer no from the audit trail alone.

## Threat Model

### Assets
- Model inference endpoints (GPU-bound, expensive)
- Tenant data in prompts and responses
- System prompts and configuration
- GPU resources (shared across tenants)

### Threat Actors
- **Malicious end users** — prompt injection, data exfiltration, model abuse
- **Compromised tenants** — lateral movement via shared GPU, cost abuse
- **Supply chain** — malicious model weights, poisoned dependencies

### Attack Vectors and Mitigations

| Attack | Vector | Mitigation | Status |
|---|---|---|---|
| Prompt injection | User input manipulates model behavior | Regex pattern matching + blocked patterns | Implemented (text-content chats only — see multimodal row) |
| Prompt injection (encoded) | Unicode/encoding tricks bypass regex | Normalize input before checking | TODO |
| Multimodal content bypass | OpenAI chat `content` sent as an array of parts (text/image/audio) doesn't match our string-typed decoder, so it reaches upstream without regex/PII/Guardrails inspection | The middleware emits an audit event with `action: "passthrough"` and `reason: "body does not match chat schema"` so the request is visible on `/v1/audit/stream`; it is **audited but not inspected** — real inspection (json.RawMessage-based extraction of text parts, and a policy decision on what to do with image/audio parts) is scoped follow-up | Audited, not inspected |
| Data exfiltration via output | Model leaks PII, secrets, system prompt | Output scanning + PII redaction + secret masking | Implemented |
| Model DoS | Large prompts or rapid requests exhaust GPU | Token-aware rate limiting per tenant | Implemented |
| Cost abuse | Tenant generates excessive inference cost | Per-tenant budget enforcement | Implemented (types), TODO (enforcement) |
| Tenant isolation breach | Shared GPU leaks data between tenants | Network policies + separate model instances per tenant | Partial |
| Supply chain | Malicious model weights | Allowed registries list, image signing | TODO |
| Credential theft | API keys in transit or logs | TLS enforcement, secret masking in audit logs | Partial |

### OWASP LLM Top 10 Coverage

| # | Risk | Coverage |
|---|---|---|
| LLM01 | Prompt Injection | Implemented for text-content chats — 13 injection patterns + custom blocked patterns. Multimodal content-as-array reaches upstream audited-but-uninspected until the multimodal parser lands (see threat table above). |
| LLM02 | Insecure Output Handling | Implemented — output scanning for PII, XSS, SQL injection, commands, secrets |
| LLM03 | Training Data Poisoning | Out of scope (model training, not serving) |
| LLM04 | Model Denial of Service | Implemented — token-aware rate limiting, max prompt token limits |
| LLM05 | Supply Chain Vulnerabilities | TODO — dependency scanning, image signing, SBOM |
| LLM06 | Sensitive Information Disclosure | Implemented — PII detection, secret masking, prompt leakage detection |
| LLM07 | Insecure Plugin Design | Partial — tool endpoint validation in inferctl |
| LLM08 | Excessive Agency | TODO — tool call allow-listing, output action constraints |
| LLM09 | Overreliance | Out of scope (application-level, not infra) |
| LLM10 | Model Theft | Partial — network policies restrict egress |

## Dependency Management

- Dependencies are pinned in go.mod
- TODO: Automated vulnerability scanning via GitHub Dependabot or Trivy
- TODO: SBOM generation via Syft
