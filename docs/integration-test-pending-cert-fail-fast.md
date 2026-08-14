# Integration Test Protocol — Pending-Cert Fail-Fast (EVBL-47)

**Goal:** Verify that a pending certificate that fails with a **terminal** error
(broken DNS delegation / no DNS provider / bad ACME credentials) is attempted **once**
and marked resolved — it must **not** be re-queued and re-run the ACME order/challenge,
which is what burned Let's Encrypt's rate limit.

**Fix under test:** `pending_certificate_service.is_terminal_failure()` + usage in
`fetch_acme_cert` (celery) and the pending-cert CLI. PR #368.

---

## 1. Deploy the change to staging

Follow the staging deploy runbook (`docs/lemur/commands.md` — `staging-manual` Conductor
target). After deploy, confirm the running image contains the fix:

```bash
kubectl --context gizmo.us1.staging.dog -n cert-orchestration \
  get pods -l app.kubernetes.io/name=lemur
```

Grep the lemur pod for the new log line source to confirm the code is live (optional):
```bash
kubectl --context gizmo.us1.staging.dog -n cert-orchestration \
  logs -l app=lemur --since=2h | grep -i "is_terminal_failure\|Terminal failure"
```

## 2. Create a pending certificate that will fail terminally

Pick a CN whose domain has **no DNS provider configured** in Lemur (or a domain with
broken ACME CNAME delegation). This guarantees a deterministic terminal failure —
retrying cannot succeed — so it is the exact case the fix targets.

Create it via the Lemur API (or `dc boot` on a throwaway DC with that CN). Example via
the Lemur API:

```bash
curl -sS -X POST "$LEMUR_BASE_URL/api/1/certificates" \
  -H "Authorization: Bearer $LEMUR_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "commonName": "*.invalid-nodns.<test-domain>",
    "owner": "rdna@datadoghq.com",
    "authority": {"name": "LetsEncryptStaging2"},
    "keyType": "RSA2048",
    "validityStart": "'"$(date -u +%Y-%m-%dT%H:%M:%S)"'",
    "validityEnd": "'"$(date -u -v+1y +%Y-%m-%dT%H:%M:%S 2>/dev/null || date -u -d '+1 year' +%Y-%m-%dT%H:%M:%S)"'",
    "rotation": false,
    "notify": false,
    "destinations": []
  }'
```

Creating the pending cert auto-triggers `fetch_acme_cert` (countdown=5s), which will hit
the terminal failure.

## 3. Confirm it is attempted only ONCE

### 3a. Watch the lemur/celery logs

Tail the celery-worker logs for the pending-cert task:

```bash
kubectl --context gizmo.us1.staging.dog -n cert-orchestration \
  logs -l app=lemur --since=10m | grep -iE "Pending certificate|Terminal failure|new_order|fetch_acme_cert"
```

**Expected (with the fix):**
- Exactly **one** `fetch_acme_cert` run for that pending cert id.
- A log line **`Terminal failure, resolving pending certificate`** (celery) / **`Terminal failure, marking pending certificate as resolved`** (CLI).
- **No** repeated `new_order` / ACME order creation for the same CN.
- **No** re-queue of `fetch_acme_cert` for that id.

**Without the fix (regression to confirm the test is valid):** the same cert would show
`number_attempts` incrementing and `fetch_acme_cert` re-queued up to `ACME_ADDITIONAL_ATTEMPTS`
times, each creating a new ACME order.

### 3b. Confirm the pending cert is marked resolved

Query the pending certificate in Lemur:

```bash
curl -sS "$LEMUR_BASE_URL/api/1/pendingcertificates?filter=cn;\"*.invalid-nodns.<test-domain>\"" \
  -H "Authorization: Bearer $LEMUR_TOKEN"
```

**Expected:** `resolved: true`, `number_attempts: 0` (never incremented), status reflecting
the terminal error — **not** a string of repeated attempts.

## 4. Negative control (optional, transient path still retries)

To confirm we did not disable retries for *transient* failures, create a pending cert that
fails with a transient error (e.g. DNS propagation not yet settled). It should still
increment `number_attempts` and re-queue (bounded by `ACME_ADDITIONAL_ATTEMPTS`), proving
the fix only short-circuits terminal failures.

## Pass criteria

- [ ] Terminal-failure pending cert attempted **exactly once** (single `fetch_acme_cert`, no re-queue).
- [ ] Log contains `Terminal failure, resolving pending certificate`.
- [ ] Pending cert `resolved=true`, `number_attempts=0`.
- [ ] No new ACME order created on retry for the failing CN.
- [ ] Transient-failure pending cert still retries (bounded) — no regression.

## Cleanup

Delete the throwaway pending cert(s) and any test DC after validation:
```bash
# via Lemur API or UI: delete the pending cert(s) created for this test
```
