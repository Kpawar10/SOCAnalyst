# CI/CD

The actual GitHub Actions workflow lives at `.github/workflows/ci-cd.yml`
(GitHub only picks up workflows from that exact path). It's referenced here
because it's conceptually part of the Cloud/DevOps/Security Engineer's
ownership area alongside `infra/terraform/`.

Pipeline stages:

1. **lint-and-test** — ruff lint, fully-mocked unit tests (`tests/test_pipeline.py`,
   `tests/test_guardrails.py`), and the static half of the red-team suite
   (`tests/redteam/prompt_injection_tests.py -m "not live"`). No network or
   secrets required; runs on every PR.
2. **live-redteam** — the live half of the red-team suite, which sends the
   adversarial payloads through the real model and asserts it didn't comply.
   Gated behind the `staging` GitHub Environment (configure a required
   reviewer there) since it costs real API tokens.
3. **build-and-push** — builds the Docker image and pushes to ECR using
   short-lived OIDC credentials (no static AWS keys in CI).
4. **terraform-plan / terraform-apply** — plans against the staging state
   file, then applies behind a manual approval gate.

## Required repo secrets

| Secret | Purpose |
|---|---|
| `AWS_DEPLOY_ROLE_ARN` | IAM role CI assumes via OIDC |
| `ANTHROPIC_API_KEY` | Used only by the live-redteam job |
| `ANTHROPIC_SECRET_ARN` | ARN of the Secrets Manager secret the running app reads its API key from |
| `TF_STATE_BUCKET`, `TF_LOCK_TABLE` | Terraform remote state backend |
| `ACM_CERT_ARN` | TLS cert for the ALB listener |
