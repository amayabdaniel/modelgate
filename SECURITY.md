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
4. **Audit everything** — every request produces an audit event with model, tenant, action, and violations
5. **Fail closed** — if a security check errors, the request is blocked, not passed through

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
| Prompt injection | User input manipulates model behavior | Regex pattern matching + blocked patterns | Implemented |
| Prompt injection (encoded) | Unicode/encoding tricks bypass regex | Normalize input before checking | TODO |
| Data exfiltration via output | Model leaks PII, secrets, system prompt | Output scanning + PII redaction + secret masking | Implemented |
| Model DoS | Large prompts or rapid requests exhaust GPU | Token-aware rate limiting per tenant | Implemented |
| Cost abuse | Tenant generates excessive inference cost | Per-tenant budget enforcement | Implemented (types), TODO (enforcement) |
| Tenant isolation breach | Shared GPU leaks data between tenants | Network policies + separate model instances per tenant | Partial |
| Supply chain | Malicious model weights | Allowed registries list, image signing | TODO |
| Credential theft | API keys in transit or logs | TLS enforcement, secret masking in audit logs | Partial |

### OWASP LLM Top 10 Coverage

| # | Risk | Coverage |
|---|---|---|
| LLM01 | Prompt Injection | Implemented — 13 injection patterns + custom blocked patterns |
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
