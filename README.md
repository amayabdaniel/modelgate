# modelgate

Gateway API Inference governance pack for Kubernetes.

Token-aware routing. Per-tenant budgets. Prompt security. Audit trails.

## The problem

Kubernetes created Gateway API Inference Extension because LLM routing needs model-aware logic. But the extension is just the routing primitive — nobody has built the production governance layer on top: budget enforcement, prompt injection protection, PII redaction, and audit logging.

Teams glue together LiteLLM + OPA + custom scripts + Prometheus alerts. It breaks.

## What modelgate does

A Helm-deployable governance pack that ships:

- **Token-aware rate limiting** — limit by tokens/min, not just requests/sec
- **Per-tenant budget enforcement** — hard and soft limits with alerts
- **Prompt security** — injection detection, PII redaction, output validation
- **Audit trails** — append-only event log per request with OTel traces
- **Model routing policies** — route by prompt size, cost tier, or tenant

```yaml
apiVersion: inference.modelgate.io/v1alpha1
kind: InferencePolicy
metadata:
  name: production
spec:
  budgets:
    - tenant: support-team
      monthly_limit_usd: 3000
      alert_at_percent: 80
  security:
    prompt_injection_protection: true
    pii_redaction: true
    blocked_patterns:
      - "ignore previous instructions"
      - "system prompt"
  routing:
    rules:
      - if: prompt_tokens < 2000
        model: qwen3-8b
      - if: prompt_tokens >= 2000
        model: llama3-70b
```

Built on Gateway API Inference Extension. Works with Envoy, Istio, or any conformant gateway.

## Status

Early development. See `projectz/potential-projectz.md` for full plan.

## License

Apache 2.0
