# Lemur Certificate Orchestration

Datadog's fork of [Netflix/Lemur](https://github.com/netflix/lemur) — a TLS certificate lifecycle management platform (web UI + REST API). Upstream docs: https://lemur.readthedocs.io/en/latest/

**Deployments** (Kubernetes namespace: `cert-orchestration`):
- Sandbox: `https://lemur-sandbox.us1.staging.dog`
- Commercial: `https://lemur-commercial.us1.ddbuild.io`
- Government: `https://lemur-government.us1-build.fed.dog` (AppGate required; FIPS images)

## Critical Constraints

- **Do not bump `cryptography==43.0.1`** — exact version required for FIPS compatibility; bumping it breaks the Government deployment
- **Source syncs must stay sequential** — parallelizing them floods the Celery queue (this was an explicit bug fix, commit `0ad9ef89`)
- **Keep `requirements-base.in` and `requirements-datadog.in` separate** — upstream Netflix/lemur changes go in `requirements-base.in`; Datadog additions (Azure/GCP integrations, CVE overrides, version pins) go in `requirements-datadog.in`
- **The Celery beat schedule is in k8s-resources, not this repo** — to change a task schedule, edit `chart/config/lemur.conf.py` in [k8s-resources](https://github.com/DataDog/k8s-resources/tree/master/k8s/lemur), not `lemur/common/celery.py`
- **Government deployment has no Sectigo** — DigiCert only; don't add Sectigo config to the gov values file

## Configuration Lives in Separate Repos

### App config & Helm — [k8s-resources](https://github.com/DataDog/k8s-resources/tree/master/k8s/lemur)

```
chart/
  config/lemur.conf.py       # Application config (rendered from Vault via consul-template)
  values.yaml                # Image tag for scheduled staging→prod deploys; staging-manual uses BUILD.bazel
  values/environments/
    us1.staging.dog.yaml
    us1.ddbuild.io.yaml
    us1-build.fed.dog.yaml
service.datadog.yaml         # Conductor schedule: staging=every commit, commercial/gov=Mon–Fri 12/14 UTC
```

Secrets are pulled from Vault at pod startup:
- Non-gov: `kv/data/k8s/cert-orchestration/lemur/`
- Gov: `kv/k8s/cert-orchestration/lemur/`

### Infrastructure — [cloud-inventory](https://github.com/DataDog/cloud-inventory)

PostgreSQL and Redis are managed via Terraform in cloud-inventory (the `terraform/` directory inside k8s-resources is obsolete):

| Environment | RDS | ElastiCache |
|-------------|-----|-------------|
| Staging | `datacenters/us1.staging.dog/lemur-db` | `datacenters/us1.staging.dog/lemur-cache` |
| Commercial | `datacenters/us1.ddbuild.io/lemur-db` | `datacenters/us1.ddbuild.io/lemur-cache` |
| Government | `datacenters/us1-build.fed/lemur-db` | `datacenters/us1-build.fed/lemur-cache` |

## Running Locally

### Docker (recommended)
```bash
cd local && docker-compose up -d   # starts lemur, postgres, redis, nginx
# UI at https://localhost:447
docker exec -u lemur -it <container_id> bash
```

### Without Docker
```bash
python3 -m venv venv && source venv/bin/activate
docker compose up -d postgres redis
make develop
export SQLALCHEMY_DATABASE_URI=postgresql://lemur:lemur@localhost:5432/lemur
cd lemur && lemur db upgrade
lemur -c <config_file> start
```

## Testing & Linting
```bash
make test          # lint + pytest (full suite)
make test-python   # pytest only
make lint-python   # flake8, max line length 100
```

PostgreSQL is required — provided by `docker-compose.yml`. Fixtures are in `lemur/tests/factories.py`.

## Database Migrations

Always run after pulling:
```bash
cd lemur && lemur db upgrade
```

After model changes, review the auto-generated file before committing:
```bash
cd lemur && lemur db migrate -m "description"
# review lemur/migrations/versions/<new file> carefully
```

> **Important:** to find the true current DB head in a running environment, check on the pod — not the local codebase:
> ```bash
> kubectl exec -n cert-orchestration deploy/lemur -- lemur db heads
> ```

## Dependencies

- `requirements.in` — upstream base (compiled to `requirements.txt`)
- `requirements-datadog.in` — Datadog overlay (see Critical Constraints above)
- `requirements-dd-source.in` — dd-source packages (COA plugin, `dd_internal_authentication`), installed separately by the Dockerfile
- Run `make up-reqs` inside a virtualenv to recompile all `.txt` files

## Telemetry (commercial instance)

- **Service tag**: `service:lemur`
- **APM**: https://app.datadoghq.com/apm/entity/service%3Alemur
- **Dashboard**: https://app.datadoghq.com/dashboard/dm6-549-pqh
- **Monitors** (prefixed `[Lemur]`): https://app.datadoghq.com/monitors/manage?q=%22%5BLemur%5D%22&p=1

### Metric tag convention (CLOUDR-2084)

| Tag | Meaning | Source | Example values |
|-----|---------|--------|----------------|
| `env` | Lemur deployment tier | k8s pod label (`tags.datadoghq.com/env`) — **never set in Python metric_tags** | `development`, `commercial`, `gov` |
| `datacenter` | Physical location where a cert is deployed | destination/plugin description JSON field `"datacenter"` | `us1`, `us2`, `eu1`, `ap1` |
| `source` | Lemur source label managing the endpoint | `endpoint.source.label` | `aws-commercial`, `gcp-eu1` |


> [!NOTE] some metrics use the stale `staging` and `prod` env tags.
 
Rules for adding metrics:
- **Do not** put a physical location value in an `env` metric tag — `env` is set globally by the Datadog agent from k8s labels.
- **Do** add `datacenter` to any metric describing where a cert was deployed. Source it from `destination.description` JSON via `_parse_destination_description()` in `certificates/service.py` (or the analogous `_datacenter_from_description()` in `certificates/models.py`).
- **Do** add `source` to endpoint-scoped metrics using `endpoint.source.label`.

## Release Process

Master commits build a prod-signed image via GitLab CI, tagged `v<pipeline_id>-<short_sha>` and re-tagged `mutable-latest-prod`.

## Deploying

### Variables

```bash
CLUSTER="gizmo.us1.staging.dog"
NAMESPACE="cert-orchestration"
DEPLOYMENT="lemur"
CONTAINER="lemur"
REGISTRY="registry.ddbuild.io/lemur"
```

### 1. Get image tag from GitLab

`gh run list` returns GitHub Actions only — use GitLab API for the build.

```bash
# Find latest successful pipeline for a branch
PIPELINE_ID=$(curl -s \
  "https://gitlab.ddbuild.io/api/v4/projects/DataDog%2Flemur/pipelines?ref=<BRANCH_URL_ENCODED>&per_page=5" \
  -H "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  | jq -r '[.[] | select(.status == "success")][0].id')

# Get the build-stage-image job ID
JOB_ID=$(curl -s \
  "https://gitlab.ddbuild.io/api/v4/projects/DataDog%2Flemur/pipelines/${PIPELINE_ID}/jobs?per_page=50" \
  -H "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  | jq -r '.[] | select(.name == "build-stage-image") | .id')

# Extract IMAGE_TAG and DIGEST from job log
curl -s \
  "https://gitlab.ddbuild.io/api/v4/projects/DataDog%2Flemur/jobs/${JOB_ID}/trace" \
  -H "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  -o /tmp/lemur-build-log.txt

IMAGE_TAG=$(grep 'Image tag:' /tmp/lemur-build-log.txt | grep -oE 'v[0-9]+-[a-f0-9]+')
DIGEST=$(crane digest ${REGISTRY}:${IMAGE_TAG})
echo "IMAGE_TAG=${IMAGE_TAG}  DIGEST=${DIGEST}"
```

### 2. Deploy to staging-manual (without merging to master)

> ⚠️ Do NOT merge to master just to test — that triggers the scheduled `staging-prod` run (Mon–Fri 16:00 UTC).

```bash
cd ~/go/src/github.com/DataDog/k8s-resources
git checkout -b <YOUR_BRANCH>   # e.g. evan/lemur-test

# Inline tag and digest
sed -i '' "s|tag = \".*\"|tag = \"${IMAGE_TAG}\"|" k8s/lemur/chart/BUILD.bazel
sed -i '' "s|digest = \"sha256:.*\"|digest = \"${DIGEST}\"|" k8s/lemur/chart/BUILD.bazel
grep -E 'tag|digest' k8s/lemur/chart/BUILD.bazel   # verify

git add k8s/lemur/chart/BUILD.bazel
git -c commit.gpgsign=false commit -m "lemur: staging-manual ${IMAGE_TAG}"
git push origin <YOUR_BRANCH>

ddr conductor run --target staging-manual --branch <YOUR_BRANCH> lemur
```

Service catalog: https://sdp.ddbuild.io/#/services/details?name=lemur&service_tab=conductor

### 3. Verify deployment

```bash
kubectl config use-context ${CLUSTER}
kubectl rollout status deployment/${DEPLOYMENT} -n ${NAMESPACE} --context ${CLUSTER}

# Confirm image (must match IMAGE_TAG, NOT mutable-latest-prod)
kubectl get deployment ${DEPLOYMENT} -n ${NAMESPACE} --context ${CLUSTER} \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="'${CONTAINER}'")].image}{"\n"}'
```

### 4. Sandbox access

```bash
export LEMUR_TOKEN=$(ssh workspace-evan-lemur '/usr/local/bin/workspace_secret LEMUR_SANDBOX_API_KEY')
LEMUR_URL="https://lemur-sandbox.us1.staging.dog"

# Sanity check
curl -s -H "Authorization: Bearer ${LEMUR_TOKEN}" \
  "${LEMUR_URL}/api/1/destinations?count=5" | jq '.items[].label'
```

> Note: `workspace_secrets`/`workspaces` are shell aliases (interactive only). Always use `/usr/local/bin/workspace_secret` (singular) in non-interactive SSH commands.

### 5. Prod promote

Merge to master — the scheduled `staging-prod` conductor run (Mon–Fri 12/14 UTC) picks it up automatically.

### Cleanup after staging test

```bash
cd ~/go/src/github.com/DataDog/k8s-resources
git checkout master && git pull
git branch -D <YOUR_BRANCH>
git push origin --delete <YOUR_BRANCH>
```

### Rollback (emergency)

```bash
kubectl rollout undo deployment/${DEPLOYMENT} -n ${NAMESPACE} --context ${CLUSTER}
kubectl rollout status deployment/${DEPLOYMENT} -n ${NAMESPACE} --context ${CLUSTER}
```

## Common Gotchas

| Symptom | Cause | Fix |
|---------|-------|-----|
| `403` push to `k8s-resources` | origin points at archived `DataDog/` repo | `git remote set-url origin git@ddoghq.github.com:ddoghq/k8s-resources.git` |
| Conductor "sourcing stage failed" | git-mirror lag after push | Wait 5–10 min, re-trigger `ddr conductor run …` |
| Deploy shows `mutable-latest-prod` after conductor run | Deploy did not land | Re-check conductor output, confirm `staging-manual` target, re-run |
| `gpg: signing failed` on commit | SSH agent unavailable for ddoghq remote | Add `-c commit.gpgsign=false` to `git commit` |

## Runbooks & References
- Wiki: https://datadoghq.atlassian.net/wiki/spaces/NE/pages/2130608302/Lemur+Certificate+Orchestration
- Runbooks: https://datadoghq.atlassian.net/wiki/spaces/NE/pages/2591327746/Lemur+Certificate+Orchestration+Runbooks
- Upstream docs: https://lemur.readthedocs.io/en/latest/
- App config: https://github.com/DataDog/k8s-resources/tree/master/k8s/lemur
