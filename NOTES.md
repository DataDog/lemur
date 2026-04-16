# RDNA-926: Non-Linear Certificate Chain Import — Implementation Notes

## What was completed

All 5 steps from the plan were implemented and committed:

1. **Test PEM fixtures** (`lemur/tests/vectors.py`): Cross-signed certificate hierarchy with Root A, Root B, intermediate signed by both roots (same key), leaf, orphan CA, and cross-signed root. Keys were regenerated after the initial set had corrupted PEM encoding.

2. **Regression tests for linear validator**: 6 tests covering full chain, partial chain, wrong chain, wrong second cert, and custom error class.

3. **Non-linear chain tests**: 4 tests covering dual-chain bundles (both orderings), orphan rejection, and cross-signed root (DigiCert pattern).

4. **DAG validator** (`lemur/common/validators.py`): Replaced the linear walk in `verify_cert_chain()` with a connectivity-from-leaf algorithm. Starting from `certs[0]`, it walks all signature relationships transitively and rejects any cert not reachable from the leaf.

5. **`check_integrity()` tests**: 3 tests exercising `Certificate.__init__()` with non-linear chains (with private key, without private key, and with orphan for rejection). This is the path that matters for source sync round-trips.

## Test results

- 21 tests pass (10 `verify_cert_chain` + 3 `check_integrity` + 8 existing upload schema tests)
- 1 preexisting failure (`test_certificate_upload_schema_ok`) — unrelated to this work; it fails because the CSR validation path requires `g.identity` which isn't set up correctly when the test includes a CSR field. This test was already failing before this branch.

## Deviations from the plan

1. **Error message format changed**: The DAG validator reports orphaned certs differently from the linear validator. Old: `"'X' is not signed by 'Y'"`. New: `"'X' is not signed by any certificate in the chain"`. Existing tests in `test_certificate_upload_schema_wrong_chain` and `_wrong_chain_2nd` were updated to match. This is a behavioral change visible to API consumers who parse error messages.

2. **PEM fixtures regenerated**: The initial fixture generation produced keys with corrupted PEM encoding (lines that didn't match the cert's public key). All fixtures were regenerated in a second pass with explicit key-cert match verification.

3. **Cross-signed root test not xfail**: `test_verify_cert_chain_cross_signed_root` was originally planned as xfail, but it turns out the linear validator also passes this case because both Root A certs (self-signed and cross-signed) share the same public key. Kept as a regular passing test.

4. **No cycle test**: The plan mentioned a cycle test (cert A signs B, B signs A). This is impossible with well-formed X.509 certs (you can't create a signature cycle without the private key of both), and generating such fixtures synthetically would require non-standard tooling. The DAG algorithm handles cycles safely via the `reached` set — it won't revisit already-reached certs. Documenting this rather than testing it.

## Needs human review before merge

1. **Error message change**: API consumers that parse the chain validation error message will see a different format. Check if any automation or monitoring relies on the old message format.

2. **Performance**: The DAG algorithm is O(n²) in the number of certs (for each visited cert, it checks all candidates). For typical chains (2-5 certs), this is negligible. For pathological inputs with many certs, it could be slower than the linear O(n) walk. This is acceptable given the use case.

3. **UnsupportedAlgorithm handling**: When a cert pair can't be verified due to an unsupported algorithm (e.g. RSASSA-PSS), the DAG validator marks the candidate as reached (same as the old validator skipping the check). This is the conservative choice to avoid false rejections, but means an unsupported-algorithm cert could mask an orphan. The old validator had the same limitation.

4. **Preexisting test failure**: `test_certificate_upload_schema_ok` fails on this branch and on master. Consider fixing separately (the `g.identity` / `SensitiveDomainPermission` issue in the CSR validation path).
