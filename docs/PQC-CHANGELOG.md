# Post-quantum phase: every change made to the code

This is the complete record of the changes that turned the classical testbed into a
post-quantum one: **ML-DSA (FIPS 204) for every signature we control** and **ML-KEM
(hybrid X25519MLKEM768) for key exchange**, with library code instead of hand-written
crypto wherever a library exists.

Baseline: the classical implementation (Methods A/B certificate-bound, Method C DPoP)
that passed 46/46 security cases.

---

## 0. The one constraint that shapes everything

Keycloak 26.6 runs on Java 21. It can neither sign tokens with ML-DSA, nor terminate
TLS with an ML-DSA certificate, nor negotiate ML-KEM. It therefore stays classical and
keeps doing what it is good at: authenticating the xApp and applying the realm
authorization policy. Everything after that is post-quantum:

| Leg | Classical mode | Post-quantum mode |
|---|---|---|
| xApp to Keycloak (token request) | EC P-256 cert, X25519 | unchanged (EC P-256 cert) - Keycloak limitation |
| xApp to RIC CA (enrollment/rotation) | EC P-256 | **ML-DSA-65 certificates, X25519MLKEM768** |
| xApp to pq-shim (token upgrade) | n/a | classical cert + **ML-DSA proof**, X25519MLKEM768 |
| xApp to resource xApp | EC P-256, RS256 token | **ML-DSA-65 certificate and token, X25519MLKEM768** |
| Token signature | RS256 (Keycloak) | **ML-DSA-65 (shim)** |
| DPoP proof (Method C) | ES256 | **ML-DSA-44** |

## 1. Libraries adopted (replacing hand-written code)

| Concern | Before | Now |
|---|---|---|
| JWS signing and verification, JWK parsing, RFC 7638 thumbprints | hand-written in `internal/jose` (~450 lines: alg registry, ECDSA/RSA/EdDSA verifiers, JWK parsing, thumbprint canonicalisation) | **`github.com/lestrrat-go/jwx/v4`** - one call per operation, ML-DSA and AKP included |
| ML-DSA primitives | n/a | **`crypto/mldsa`** (Go 1.27 standard library, FIPS 204) |
| ML-DSA certificates and CSRs | n/a | **`crypto/x509`** (Go 1.27 supports ML-DSA keys, signatures, CSRs) |
| ML-KEM key exchange | n/a | **`crypto/tls`** (`X25519MLKEM768`, and `ConnectionState.CurveID` to observe it) |

Everything that remains hand-written is *policy*, not cryptography: the binding
comparisons (`x5t#S256`, `jkt`, `ath`), the replay cache, the rejection reasons, the
CA issuance policy, and the binding-transfer protocol.

## 2. New files

| File | Purpose |
|---|---|
| `internal/pqbind/pqbind.go` | Shared constants for the binding-transfer proof (`X-PQ-Proof`, `pq-binding+jwt`) |
| `pqshim/shim.go` | The post-quantum token shim: verifies the classical token and its binding, verifies the ML-DSA proof of possession, mints the ML-DSA-signed token, serves JWKS and introspection |
| `pqshim/cmd/pq-shim/main.go` | Shim binary (TLS server, plain-HTTP health port) |
| `pqshim/k8s/pq-shim.yaml` | Shim Deployment and Service in `ricsec` |
| `ca/cmd/pki-gen/main.go` | Generates the ML-DSA PKI (root, onboarding CA, RIC intermediate CA, server certificates) with `crypto/x509`, because OpenSSL 1.1.1 on the VM predates ML-DSA |
| `xapp-client/pq.go` | Client side of the upgrade: builds the ML-DSA proof (certificate chain in `x5c` or AKP key in `jwk`) and calls the shim |
| `cmd/methodrun/main.go` | CLI that walks one method end to end and prints every step |
| `scripts/_run-method.sh`, `scripts/run-method-{a,b,c}.sh` | The three run scripts |
| `docs/PQC-CHANGELOG.md` | This document |

## 3. Changed files, one by one

### `internal/jose` (rewritten on top of jwx)
- **Deleted** `alg.go`, `jwk.go`, `jws.go`, `jwks.go` as hand-written implementations.
- `jose.go` (new): `LookupAlg` refuses `none` and symmetric algorithms and maps the
  `alg` header to a jwx algorithm; `JWK.PublicKey()` refuses keys carrying private
  members (`d`, `priv`, ...) and delegates conversion to jwx; `JWK.Thumbprint()`
  delegates to jwx, which applies the RFC 9964 member set (`alg`, `kty`, `pub`) for AKP keys.
- `jws.go`: `ParseCompact` keeps the compact form for verification; `VerifySignature`
  now calls `jws.Verify` - the same call verifies ES256 and ML-DSA-65.
- `signer.go`: `Signer` produces a whole compact JWS (`SignCompact`) instead of raw
  signature bytes; `GenerateSigner` supports ES256/384/512 and **ML-DSA-44/65/87**.
- `jwks.go`: `KeySet` parses with `jwk.Parse` (AKP included) and the response limit was
  raised to 4 MB because ML-DSA public keys are kilobytes.
- Removed: `RegisterVerifier`, `RegisterSigner`, `RegisterKeyType`, `RegisteredAlgs`,
  `JWKFromPublicKey`, the ECDSA/RSA/EdDSA verifier implementations and the manual
  RFC 7638 canonicalisation. jwx is the registry now.
- `jose_test.go`: keeps the RFC 7638 vector, adds a sign/verify/thumbprint/forgery
  round trip for **ES256, ES384, ML-DSA-44, ML-DSA-65, ML-DSA-87**, and asserts that an
  ML-DSA key serialises as an AKP JWK without leaking `priv`.

### `internal/pki/pki.go`
- `GenerateKey` gained `ML-DSA-44/65/87` (via `crypto/mldsa`).
- Added `IsPostQuantum`, `KeyAlgName` and `DescribeCert` (used by the CA to pick an
  issuing branch, and by the CLI and logs to show what is in use).

### `internal/netx/netx.go`
- Added `CurvePreferences(pqOnly bool)`: with `pqOnly` the connection offers only
  `X25519MLKEM768`, so a classical-only peer fails the handshake instead of silently
  negotiating a quantum-vulnerable key exchange. Added `IsPQKex`.

### `internal/smo/bootstrap.go`, `ca/cmd/smo-sim`
- `Onboarding.KeyAlg` selects the bootstrap key type, so the ML-DSA onboarding CA
  issues ML-DSA bootstrap credentials (onboarding itself is post-quantum).
- `smo-sim` gained `-key-alg` and prints the key algorithm.

### `ca/enroll/server.go` (dual-issuer CA)
- One issuing branch per signature family (`classical`, `post-quantum`), selected by
  the **key type in the CSR** (`branchFor`): an ML-DSA CSR is signed by the ML-DSA CA.
  Enrollment, lifetime policy, one-time bootstrap ledger and rotation are unchanged and
  shared, so Method B rotation works for post-quantum certificates too.
- `ISSUER_CERT_PQ` / `ISSUER_KEY_PQ` added; `BOOTSTRAP_TRUST_BUNDLE` and
  `OPERATIONAL_TRUST_BUNDLE` became lists so both CA families are trusted.
- `parseCSR` accepts `*mldsa.PublicKey`.
- `/v1/ca-chain` returns both issuing certificates.
- Issuance log now records `issuer_branch`, `key_alg`, `sig_alg` and `cert_bytes`.
- TLS gained `CurvePreferences` (`PQ_KEX_ONLY`).

### `ca/scripts/gen-pki.sh`
- The classical branch is unchanged but now skippable; the script always calls
  `pki-gen` for the post-quantum branch.

### `xapp-client` (dual credential planes)
- `config.go`: `TrustBundle` became a list; added `PQEnabled`, `PQShimURL`, `PQKeyAlg`,
  `PQDPoPAlg`, `PQCertLifetime`, `PQBootstrap*`, `PQIdentityDir`, `PQKexOnly`,
  `PQProofValidity`, `PQUpgradeTimeout`, plus validation (PQ algorithms must be ML-DSA)
  and `upgradeURL()`.
- `client.go`: introduced the **plane** abstraction (`classicalPlane`, `pqPlane`). One
  set of enrollment/renewal/rotation functions now serves both credentials; the client
  holds two identities, two transports (the post-quantum one pinned to ML-KEM), and
  `HTTPClient()` returns the post-quantum transport in PQ mode. Added `PQIdentity()`
  and `Describe()`. `Token` gained `Alg`, `PostQuantum` and `Classical`.
- `identity.go`: `RotationStats` gained `KeyAlg`, `CertBytes` and `Plane`; `Enroller`
  gained `PQKexOnly`.
- `certbound.go` (Methods A/B): after Keycloak issues the classical token, the client
  upgrades it through the shim and re-checks that the new `cnf.x5t#S256` is the
  thumbprint of its **own** ML-DSA certificate (fail closed, exactly as with Keycloak).
- `dpop.go` (Method C): holds a second, ML-DSA proof key; the upgrade request proves
  possession of the classical key with an ordinary DPoP proof and of the ML-DSA key
  with the binding proof; resource requests are signed with whichever key matches the
  token (`proofFor`). `BuildDPoPProof` is algorithm-agnostic, so it produces ES256 and
  ML-DSA-44 proofs from the same code.
- `pq.go` (new): the upgrade call and the two proof builders.

### `xapp-resource`
- `config.go`: `TrustBundle` became a list (classical and post-quantum anchors).
- `validator.go`: only the trust-pool call changed. **The binding logic is untouched**:
  `x5t#S256`, `jkt` and `ath` are SHA-256 values, so they are algorithm-agnostic, and
  the token signature is verified through jwx by the `alg` in the header. This is the
  practical proof that the phase-1 design did not block the post-quantum phase.

### `demo-xapp`
- Added a plain-HTTP health endpoint (`HEALTH_ADDR`, default `:8081`): the kubelet
  probe client predates ML-KEM and cannot handshake on a PQ-only TLS port.

### Deployment
- `config/testbed.env`: added the post-quantum block (`PQ_MODE`, shim service/port,
  `PQ_SIGNING_ALG`, `PQ_IDENTITY_KEY_ALG`, `PQ_DPOP_ALG`, PKI parameter sets,
  `PQ_KEX_ONLY`, `PQ_TOKEN_LIFETIME`).
- `Makefile`: derived `PQ_SHIM_URL`; mode-dependent `RESOURCE_TOKEN_ISSUER`,
  `RESOURCE_JWKS_URL`, `RESOURCE_INTROSPECTION_URL` and `RIC_CA_SERVER_CERT`; the
  `pki` target builds and runs `pki-gen`; `trust` publishes the post-quantum anchors;
  `deploy-ca` also creates the ML-DSA issuer secret; new `deploy-shim`; the xApp
  bootstrap now issues a second, ML-DSA credential; new targets `pq-up`,
  `classical-up`, `run-a`, `run-b`, `run-c`; `pq-shim` added to the images.
  Secrets holding ML-DSA keys are created as `generic --type=kubernetes.io/tls`,
  because `kubectl create secret tls` (client-side parsing, kubectl 1.28) cannot read
  an ML-DSA private key.
- `ca/k8s/ric-ca.yaml`: ML-DSA issuer mount and both trust bundles.
- `demo-xapp/k8s/xapps.yaml`: post-quantum bootstrap secret and identity volume, the
  `PQ_*` settings, the health port, and the validator pointed at the active issuer.
- `build/host-env.sh`: exports the post-quantum onboarding CA, the shim URLs, the
  algorithms and the namespace names used by the scripts; `RIC_TRUST_BUNDLE` now lists
  both anchors.
- `build/render.sh`: renders the new derived variables.

## 4. The binding-transfer protocol (new, and the part worth describing in the paper)

A token bound to a classical certificate cannot simply be re-labelled as bound to a
post-quantum one: that would let anyone who holds either credential move the binding.
The shim therefore requires **proof of possession of both** credentials in one request:

```
POST /v1/upgrade                         (mTLS with the CLASSICAL certificate)
Authorization: Bearer <keycloak token>   (or DPoP + classical proof, method C)
X-PQ-Proof: <ML-DSA JWS, typ=pq-binding+jwt>
    header : alg=ML-DSA-65, x5c=[post-quantum certificate chain]   (methods A/B)
             alg=ML-DSA-44, jwk={kty:AKP,...}                      (method C)
    claims : htm, htu, iat, jti, ath=SHA-256(keycloak token)
```

The shim then:
1. validates the Keycloak token and its classical binding with the **same
   `xappresource.Validator`** a resource server uses (so the classical binding is
   re-proved, not trusted);
2. verifies the ML-DSA proof: signature, certificate chain to the post-quantum CA,
   `CN` equal to the authenticated client, `ath` over the presented token, `htm`/`htu`,
   `iat` window and unused `jti`;
3. issues a token signed with ML-DSA-65 whose `cnf` names the post-quantum credential,
   never outliving the original token, and records the provenance in `upgraded_from`.

## 5. Measured on the VM (from the run scripts)

| Quantity | Classical | Post-quantum | Factor |
|---|---|---|---|
| Identity certificate | 564 B (EC P-256) | 5,660 B (ML-DSA-65) | 10.0x |
| Access token | 1,017 B (RS256) | 5,352 B (ML-DSA-65) | 5.3x |
| DPoP proof | ~560 B (ES256) | 5,920 B (ML-DSA-44) | 10.6x |
| Token issue (method A) | 17.2 ms | 79.4 ms (Keycloak + upgrade) | 4.6x |
| Enrollment (both planes) | 11.2 ms | 55.2 ms | 4.9x |
| Method B rotation | keygen 0.06 ms, CA 9.4 ms | keygen 0.53 ms, CA 10.7 ms | ~1.1x on the CA |
| Key exchange | X25519MLKEM768 (Go 1.27 default) | X25519MLKEM768 (enforced) | - |

Note: even in classical mode Go 1.27 negotiates the hybrid ML-KEM group by default;
`PQ_KEX_ONLY=true` turns that default into a requirement.

## 6. Verified

- `go test ./...` passes, including ML-DSA sign/verify/thumbprint round trips.
- Classical mode: the full security suite still passes **46/46** after the refactor.
- Post-quantum mode: `run-method-a/b/c.sh --pq` all end with *All checks passed*,
  including the negative tests (wrong certificate, no certificate, foreign proof key,
  replayed proof, and a token bound to a rotated-away certificate).

## 7. The shim has an exit condition

`PQ_ISSUER` (default `shim`) names the service that issues the post-quantum token.
`PQ_ISSUER=keycloak` points every validator at the authorization server, makes the client
use its ML-DSA credential on that leg, and refuses any token that is not ML-DSA-signed.
No released Keycloak can do this yet (26.7.4 is current; the PQC epic sits on the
unreleased 27.0 milestone with 1 of 16 issues done), so the setting fails closed today
with a message that says why. See `docs/Implementation-4-Post-Quantum.md`, section 5, for
the evidence and for why Duende IdentityServer was evaluated and not adopted.

## 8. Known limitations

- The Keycloak leg stays classical (Java 21). An attacker recording it today could
  forge *Keycloak* tokens after a cryptographically relevant quantum computer exists;
  the shim limits the blast radius because a resource server only accepts ML-DSA tokens
  in PQ mode, but the trust chain still starts at a classical signature.
- The shim generates its ML-DSA signing key at startup (no persistence); resource
  servers refetch the JWKS when they meet an unknown `kid`.
- ML-DSA certificates are not used on the Keycloak leg, so each xApp holds two
  credentials; SPIRE-style single-credential issuance would need a PQ-capable AS.
- The benchmark harness (`bench/`) still measures the classical path only; the
  per-method numbers above come from the run scripts.
