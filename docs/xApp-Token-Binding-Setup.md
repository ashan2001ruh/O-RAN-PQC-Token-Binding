# xApp Token Binding and PQC Authorization: Setup Guide

How to bring this implementation up on a **clean OSC Near-RT RIC**, from an empty cluster to
passing security tests, in both the classical and the post-quantum configuration.

Nothing in `ricplt` is modified. Everything this project creates lives in a new `ricsec`
namespace plus a few labelled objects in `ricxapp`, and `make down` removes all of it.

---

## 1. What gets deployed

| Component | Namespace | Role |
|---|---|---|
| `ric-ca` | ricsec | RIC intermediate CA. Issues xApp identity certificates. One classical branch and one ML-DSA branch; the key type in the CSR selects the branch |
| `keycloak` | ricsec | The authorization server (XRF). Authenticates xApps over mTLS and issues sender-constrained tokens |
| `pq-shim` | ricsec | Post-quantum token shim. Re-signs the Keycloak token with ML-DSA-65 and moves the binding onto the post-quantum credential |
| `xapp-a`, `xapp-b` | ricxapp | Demo xApps. Each is an OAuth client and a protected resource, and calls the other every 30 s |
| `ric-trust` (ConfigMap) | ricsec, ricxapp | Public trust anchors |

Three binding methods are implemented:

| Method | Binding | Confirmation claim | Certificate lifetime | Keycloak client |
|---|---|---|---|---|
| A | RFC 8705 certificate-bound, long-term key | `cnf.x5t#S256` | 168 h | `xapp-longterm` |
| B | RFC 8705 certificate-bound, ephemeral key | `cnf.x5t#S256` | 15 min, rotated | `xapp-ephemeral` |
| C | RFC 9449 DPoP | `cnf.jkt` | n/a | `xapp-dpop` |

In post-quantum mode: tokens are signed with **ML-DSA-65**, identity certificates are
**ML-DSA-65**, DPoP proofs are **ML-DSA-44**, and every TLS leg we control uses
**X25519MLKEM768** (hybrid ML-KEM-768).

---

## 2. Prerequisites

### 2.1 Cluster and host

- A working OSC Near-RT RIC (this was developed against `ric-plt` with Kubernetes v1.28).
- Namespace `ricxapp` must exist (the RIC creates it).
- **At least 6 GB RAM and 4 vCPU on the node.** Keycloak alone needs about 1 GB, and the
  RIC platform is already resident. With less, Keycloak gets killed during startup.
- About 3 GB free disk for the Go toolchain, build cache and container images.
- Outbound internet access on first run (Go modules and the Keycloak image).

### 2.2 Tools on the node

```bash
kubectl version --client        # 1.28+
docker version                  # for building images
ctr --version                   # containerd CLI, for importing images
openssl version                 # 1.1.1 is fine
jq --version
envsubst --version              # package: gettext-base
make --version
```

Install anything missing, for example:

```bash
sudo apt-get update && sudo apt-get install -y jq gettext-base make
```

### 2.3 Go 1.27 or newer (required)

The post-quantum code uses `crypto/mldsa`, ML-DSA support in `crypto/x509` and the ML-KEM
hybrid group in `crypto/tls`, all of which arrived in **Go 1.27**. Distribution packages are
older, so install the toolchain into your home directory:

```bash
mkdir -p ~/tools && cd ~/tools
V=$(curl -s 'https://go.dev/VERSION?m=text' | head -1)
curl -sSL -o go.tgz https://go.dev/dl/$V.linux-amd64.tar.gz
tar xzf go.tgz && rm go.tgz
~/tools/go/bin/go version      # expect go1.27.x or newer
```

The Makefile picks up `go` from `PATH`, falling back to `~/tools/go/bin/go`.

> With an older toolchain the build fails with
> `mldsa.GenerateKey requires go1.27 or later`.

### 2.4 Shell environment

```bash
export KUBECONFIG=$HOME/.kube/config
export PATH=$HOME/tools/go/bin:$PATH
```

Building and importing container images needs root, so either run `sudo -v` first (the
credential stays cached for a while) or pass your own sudo wrapper:

```bash
make SUDO='sudo -A' up      # with SUDO_ASKPASS set, for non-interactive runs
```

---

## 3. Get the code onto the node

Copy the `xapp-token-binding` directory to the RIC node, for example:

```bash
scp -r xapp-token-binding pasindu@<ric-node>:~/
cd ~/xapp-token-binding
```

> If you edited any file on Windows, normalise line endings first, or the shell scripts fail
> with `/usr/bin/env: bash\r: No such file or directory`:
> ```bash
> find . -name '*.sh' -o -name 'Makefile' | xargs sed -i 's/\r$//'
> ```

Layout:

| Path | Contents |
|---|---|
| `config/testbed.env` | the single configuration file: namespaces, service names, ports, DNs, lifetimes, algorithms |
| `ca/` | PKI generation, the enrollment service, the SMO onboarding simulator, manifests |
| `keycloak/` | Keycloak manifest and the `ric-realm` export |
| `pqshim/` | the post-quantum token shim and its manifest |
| `xapp-client/`, `xapp-resource/` | the client library and the resource-side validator |
| `demo-xapp/` | the demo xApp and its manifests |
| `cmd/methodrun`, `scripts/` | the end-to-end walkthrough CLI and the three run scripts |
| `test/`, `bench/` | security test suite and measurement harness |

---

## 4. Review the configuration

Everything is driven by `config/testbed.env`. The defaults work unchanged; review these:

```bash
grep -E 'NAMESPACE|KEYCLOAK_IMAGE|CERT_LIFETIME|PQ_' config/testbed.env
```

| Variable | Default | Note |
|---|---|---|
| `RICSEC_NAMESPACE` | `ricsec` | created by `make up` |
| `XAPP_NAMESPACE` | `ricxapp` | must already exist |
| `KEYCLOAK_IMAGE` | pinned digest of Keycloak 26.6.0 | must be pullable, or pre-loaded into containerd |
| `LONGTERM_CERT_LIFETIME` | `168h` | Method A |
| `EPHEMERAL_CERT_LIFETIME` | `15m` | Method B |
| `PQ_MODE` | `false` | the mode the xApps are deployed in |
| `PQ_SIGNING_ALG` | `ML-DSA-65` | shim token signature |
| `PQ_KEX_ONLY` | `true` | require X25519MLKEM768 on post-quantum legs |

---

## 5. Bring the testbed up

```bash
make up
```

This runs, in order: PKI generation (classical with OpenSSL, post-quantum with
`crypto/x509`), Go build, image build and import into containerd, namespace and trust
anchors, the CA, Keycloak, the realm import, the shim, SMO onboarding of the two demo xApps,
and their deployment.

Expect **10 to 15 minutes on the first run** (module downloads, the Keycloak image pull and
its first start dominate). Later runs take about 90 seconds.

Expected tail:

```
deployment "ric-ca" successfully rolled out
realm ric-realm imported
deployment "pq-shim" successfully rolled out
deployment "xapp-a" successfully rolled out
deployment "xapp-b" successfully rolled out
testbed is up: run 'make verify-ca verify-keycloak test bench'
```

Check the pods:

```bash
make status
kubectl -n ricsec get pods
kubectl -n ricxapp get pods -l part-of=xapp-token-binding
```

---

## 6. Verify the two milestones

### 6.1 The CA issues certificates and the bootstrap credential is single use

```bash
make verify-ca
```

Expected: a leaf issued on demand, `openssl verify` returning OK, a second use of the same
bootstrap credential refused, and a long-lived certificate from the same code path:

```
==> Reusing the same bootstrap credential must be rejected
HTTP 403 {"error":"bootstrap_credential_reused", ...}
MILESTONE 1 PASSED
```

### 6.2 Keycloak binds the token to the certificate

```bash
make verify-keycloak
```

Expected: the token carries `cnf.x5t#S256` equal to the SHA-256 thumbprint of the
certificate presented, a request with no certificate gets `invalid_client`, and a
certificate from an untrusted CA is refused during the TLS handshake:

```
OK: cnf.x5t#S256 == SHA-256 thumbprint of presented certificate
MILESTONE 2 PASSED
```

> This check is mandatory, not cosmetic: Keycloak issues a token even when the client
> certificate never reaches it, simply omitting `cnf`.

---

## 7. Run the security test suite

```bash
make test
```

46 cases: positive controls for all three methods, the seven required negative tests, and
extra proof-of-possession, rotation, tampering and enrollment checks. Every case runs twice,
once with local validation and once with introspection.

```
46 cases, 46 passed, 0 failed. Results: results/security-tests.csv
```

The CSV contains the exact rejection reason for each case, which is what makes the results
quotable (`cnf_x5t_mismatch`, `client_certificate_missing`, `dpop_proof_replayed`, ...).

---

## 8. Walk through one method end to end

```bash
scripts/run-method-a.sh        # Method A
scripts/run-method-b.sh        # Method B, includes a key rotation
scripts/run-method-c.sh        # Method C, includes a DPoP proof replay
```

Each script prints: the configuration, SMO onboarding and enrollment, the token with its
binding, a resource call under local validation and under introspection, the negotiated TLS
key exchange, the method-specific behaviour, and the negative test that proves the token
alone is not enough. It then shows the matching log lines from the resource xApp, the shim
and the CA. A run ends with `All checks passed.`

---

## 9. Switch to post-quantum mode

```bash
make pq-up
```

This redeploys the CA (now presenting an ML-DSA server certificate), the shim and both demo
xApps with `PQ_MODE=true`, and repoints the resource validator at the shim as issuer.

```bash
scripts/run-method-a.sh --pq
scripts/run-method-b.sh --pq
scripts/run-method-c.sh --pq
```

What changes in the output:

```
classical certificate:     CN=xapp-longterm key=EC-P-256  ... (565 bytes)
post-quantum certificate:  CN=xapp-longterm key=ML-DSA-65 ... (5660 bytes)
Keycloak token:            alg=RS256      binding=cnf.x5t#S256 bytes=1017
upgraded token:            alg=ML-DSA-65  binding=cnf.x5t#S256 bytes=5352
TLS key exchange:          X25519MLKEM768
```

Each xApp now holds **two** credentials: a classical one used only for the Keycloak leg
(Java 21 supports neither ML-DSA nor ML-KEM) and an ML-DSA one used for the CA, the shim,
the resource server and peer xApps.

Go back with:

```bash
make classical-up
```

> **The deployment mode and the script flag must match.** Running `scripts/run-method-a.sh`
> (classical) while the xApps are deployed in PQ mode fails at the first check with
> `token_key_unavailable`, because the resource validator then trusts only the shim as
> issuer. Check the live mode with:
> ```bash
> kubectl -n ricxapp get cm xapp-token-binding -o jsonpath='{.data.PQ_MODE}{"\n"}'
> ```

### Who issues the post-quantum token

`PQ_ISSUER` names the service that signs it. The default is the shim, because no released
Keycloak can sign with ML-DSA (26.7.4 is current; the PQC epic is on the unreleased 27.0
milestone). The other value is the exit condition for the shim.

```bash
make PQ_MODE=true show-config                      # issuer = pq-shim   (today)
make PQ_MODE=true PQ_ISSUER=keycloak show-config   # issuer = Keycloak  (when it can)
```

`PQ_ISSUER=keycloak` changes three things with no code edit: every validator trusts the
authorization server instead of the shim, the client presents its ML-DSA credential on the
authorization-server leg, and any token that is not ML-DSA-signed is refused. Against
today's Keycloak it fails closed at the token request with a message explaining why, which
is the expected result:

```
FAIL token: ... remote error: tls: unexpected message
     [PQ_ISSUER=keycloak: the authorization server was offered the ML-DSA credential.
      No released Keycloak can parse an ML-DSA certificate or sign with ML-DSA;
      set PQ_ISSUER=shim]
```

To switch the whole deployment over on the day it becomes possible:

```bash
make PQ_MODE=true PQ_ISSUER=keycloak pq-up
make PQ_MODE=true PQ_ISSUER=keycloak sidecar-up
kubectl -n ricsec delete deploy pq-shim
```

---

## 10. The sidecar architecture (Kyverno injection and dms_cli onboarding)

Sections 5 to 9 deploy xApps that carry the token binding **in their own process**. This
section deploys the same security with **no xApp code at all**: a sidecar container, added
by Kyverno at admission time, that carries the traffic of a stock image over a post-quantum
tunnel and enforces the binding on it. Both HTTP and RMR traffic are covered, in both
directions. It requires the post-quantum deployment from section 9.

Full detail, including every source file, is in
`docs/Implementation-6-Sidecar-Kyverno-Onboarding.md`.

### What it adds

| Component | Where | Purpose |
|---|---|---|
| Kyverno admission controller | namespace `kyverno` | injects the sidecar from pod annotations |
| ClusterPolicy `xapp-token-binding-sidecar` | cluster | the injection rule |
| `ricsec/xapp-sidecar:0.1.0` | `ricxapp` pods | the tunnel and the enforcement point |
| `<client-id>-sidecar` Services | `ricxapp` | publish the tunnel port only |
| ChartMuseum | node, port 8090 | the chart repository `dms_cli` pushes to |
| `xappc`, `xappd` | `ricxapp` | two xApps onboarded with `dms_cli`, running stock busybox |

### Prerequisites on the node

`dms_cli` and `helm` are part of the OSC RIC install. ChartMuseum must be running and
`CHART_REPO_URL` must point at it:

```bash
sudo tee /etc/systemd/system/chartmuseum.service >/dev/null <<'EOF'
[Unit]
Description=ChartMuseum local Helm chart repository
After=network.target

[Service]
User=%i
Environment=STORAGE=local
Environment=STORAGE_LOCAL_ROOTDIR=/home/%i/chartstorage
Environment=PORT=8090
Environment=ALLOW_OVERWRITE=true
ExecStart=/usr/local/bin/chartmuseum
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

Replace `%i` with your user name, then:

```bash
mkdir -p ~/chartstorage
sudo systemctl daemon-reload && sudo systemctl enable --now chartmuseum
curl -s localhost:8090/health          # {"healthy":true}
echo 'export CHART_REPO_URL=http://localhost:8090' >> ~/.bashrc
```

### Bring it up

```bash
make pq-up                 # section 9: the post-quantum deployment the sidecar needs
make PQ_MODE=true sidecar-up
```

`sidecar-up` runs, in order: `build`, `images`, `demo-app-image`, `kyverno`,
`sidecar-policy`, `bootstrap-sidecar-xapps`, `onboard-xapps`. Individually:

```bash
make kyverno                         # admission controller only, idempotent
make demo-app-image                  # stock busybox -> 127.0.0.1:5000
make PQ_MODE=true sidecar-policy     # ClusterPolicy + the two Services
make PQ_MODE=true bootstrap-sidecar-xapps
make PQ_MODE=true onboard-xapps      # dms_cli onboard + install
```

The realm must contain the two sidecar clients; if the realm predates them:

```bash
REPLACE=1 make PQ_MODE=true import-realm
```

### Check it

```bash
make sidecar-status
```

Both pods must be `2/2`: the xApp container and the injected `pq-sidecar`.

```bash
make sidecar-logs
```

Each accepted connection logs the binding that was checked, the peer certificate, the
key exchange and the timings:

```json
{"msg":"egress_authorized","route":"http","peer_cert":"xapp-sidecar-d",
 "binding":"x5t#S256","token_alg":"ML-DSA-65","kex":"ML-KEM-768","handshake_ms":5.61}
{"msg":"ingress_authorized","route":"rmr","client_id":"xapp-sidecar-d",
 "binding":"jkt","kex":"ML-KEM-768","authz_ms":6.17,"target":"127.0.0.1:4560"}
```

The applications themselves see plain HTTP and plain TCP:

```bash
kubectl -n ricxapp logs -l pq.oran/sidecar=xapp-sidecar-c -c xappc --tail=8
```

```
[http-out] calling the peer xApp through the sidecar
[http-in] hello from xappd, served over the post-quantum tunnel
[rmr-out] sending an RMR message through the sidecar
[rmr-in] RMR:xappd:hello
```

Fail-closed check - a connection that is not a tunnel never reaches the application:

```bash
kubectl -n ricxapp run pq-probe --rm -i --restart=Never   --image=127.0.0.1:5000/oran/busybox:1.36 --command --   sh -c 'echo NOT-A-PQ-HANDSHAKE | nc -w 5 xapp-sidecar-d-sidecar.ricxapp.svc.cluster.local 4570'
make sidecar-logs   # ingress_failed: tunnel handshake: ...
```

### Onboarding your own xApp

Add five annotations to the xApp descriptor. Nothing else changes: not the image, not the
containers section, not the xApp source.

```json
"annotations": {
  "pq.oran/inject": "true",
  "pq.oran/client-id": "my-xapp",
  "pq.oran/method": "A",
  "pq.oran/ingress": "http|127.0.0.1:8080,rmr|127.0.0.1:4560",
  "pq.oran/egress": "http|127.0.0.1:18080|peer-sidecar.ricxapp.svc.cluster.local:4570|peer-xapp"
}
```

- `ingress` maps a route label to the local address the application listens on.
- `egress` maps a route label to a loopback address the application connects to instead of
  the peer, plus the peer sidecar address and the certificate subject it must present.
- The client id must exist as a Keycloak client and must have bootstrap secrets
  `<client-id>-bootstrap` and `<client-id>-bootstrap-pq` in `ricxapp`
  (`make bootstrap-sidecar-xapps` is the template for minting them).

### Remove it

```bash
make sidecar-down       # xApps, policy, Services, bootstrap secrets
helm uninstall -n kyverno kyverno    # only if Kyverno is not used for anything else
```

### Known limits

- The sidecar requires `PQ_MODE=true`; it authenticates peers with ML-DSA certificates and
  will not start without one.
- Authorization is per connection, not per request: the first record on a tunnel is the
  authorization frame, and one tunnel carries one application connection.
- The demo application ports are not firewalled. The tunnel is the only way *in through the
  sidecar*, but a NetworkPolicy restricting the application ports to loopback is what stops
  another pod from reaching them directly, and the demo does not ship one.

---

## 11. Measurements

```bash
make bench
```

Writes `results/bench.csv` (fixed schema and row order, so runs are comparable) and
`results/bench-env.csv` with the run metadata. It measures token request latency, resource
request latency and throughput under local validation versus introspection, token and proof
sizes, and for Method B the rotation cost and rotations per hour at several lifetimes.

Offline unit tests, which need no cluster:

```bash
make unit
```

---

## 12. Day-2 operations

| Command | Effect |
|---|---|
| `make status` | show the testbed pods |
| `make logs` | tail the validator decisions from the demo xApps |
| `make restart-xapps` | issue fresh bootstrap credentials and restart the demo xApps |
| `make restart-keycloak` | new Keycloak pod and realm re-import |
| `make import-realm REPLACE=1` | recreate the realm from `keycloak/ric-realm.json` |
| `make host-env` | regenerate `out/host.env` after Service IPs change |
| `make down` | remove everything this project deployed |
| `make clean` | remove build outputs, keep the PKI |

---

## 13. The Keycloak realm

Realm `ric-realm`, created through the admin API by `make import-realm`, contains:

| Client | Authenticator | Binding attribute |
|---|---|---|
| `xapp-longterm` | `client-x509`, subject DN `CN=xapp-longterm,OU=xApps,O=O-RAN-RIC` | `tls.client.certificate.bound.access.tokens=true` |
| `xapp-ephemeral` | same, `CN=xapp-ephemeral` | identical to the above |
| `xapp-dpop` | same, `CN=xapp-dpop` | `dpop.bound.access.tokens=true` |
| `xapp-unbound-probe` | same | both off, test only: proves unbound tokens are rejected |

All four use the client scope `ric-sdl-access`, which adds the audience `ric-xapps`, the
realm role `ric-sdl-access` and the subject to the access token.

The admin password is generated on first deploy and kept at
`out/secrets/keycloak-admin-password`.

---

## 14. Troubleshooting

**Keycloak restarts repeatedly during startup.**
On a loaded node the JVM stalls and the kubelet kills it. The manifest already uses 10 to
15 second probe timeouts; if it still happens, free memory (the node needs ~1 GB for
Keycloak) and retry. Check with `kubectl -n ricsec describe pod -l app=keycloak`.

**`token_key_unavailable` or `token_inactive` on every request.**
Mode mismatch: the deployed xApps and the script flag disagree. See section 9.

**`kubectl create secret tls` fails with "failed to parse private key".**
kubectl 1.28 cannot read an ML-DSA private key. The Makefile already creates post-quantum
secrets as `generic --type=kubernetes.io/tls`, which skips client-side parsing. If you add
your own secret with ML-DSA key material, do the same.

**`curl` cannot reach the shim or the CA in PQ mode.**
OpenSSL 1.1.1 cannot verify an ML-DSA certificate. This is expected; use the project Go
tools (`methodrun`, `sectest`) for the post-quantum endpoints.

**An xApp pod logs `bootstrap_credential_reused`.**
Bootstrap credentials are single use by design. A recreated pod needs a fresh one:
`make restart-xapps`.

**After a shim restart, tokens are rejected for a few minutes.**
The shim generates its ML-DSA signing key at startup, so its `kid` changes. Cached tokens
signed by the previous instance become unverifiable until they expire (5 minutes).

**Builds are slow or the node becomes unresponsive.**
`go build` is memory hungry. The Makefile already limits parallelism (`GOFLAGS=-p=2`). Avoid
building while the RIC is under load.

---

## 15. Uninstall

```bash
make down
```

Removes the `ricsec` namespace and every object labelled `part-of=xapp-token-binding` in
`ricxapp`. The RIC platform, `ricplt` and any other xApps are untouched. Local PKI and
results stay in `out/` and `results/`; delete `out/pki` to force a fresh PKI on the next run.

---

## 16. Reference

### Services and ports

| Service | Namespace | Port | TLS |
|---|---|---|---|
| `ric-ca` | ricsec | 8443 | mTLS, server certificate classical or ML-DSA by mode |
| `keycloak` | ricsec | 8443 | mTLS, `https-client-auth=request`, TLSv1.3 |
| `pq-shim` | ricsec | 8443 (plus 8081 plain HTTP for probes) | ML-DSA server certificate, ML-KEM key exchange |
| `xapp-a`, `xapp-b` | ricxapp | 8443 (plus 8081 for probes) | mTLS, identity certificate by mode |

The probe ports are plain HTTP on purpose: the kubelet probe client predates ML-KEM and
cannot complete a handshake against a PQ-only TLS port.

### Algorithms

| Purpose | Classical | Post-quantum |
|---|---|---|
| Token signature | RS256 (Keycloak) | ML-DSA-65 (shim) |
| Identity certificate | EC P-256, CA chain EC P-384 | ML-DSA-65, CA chain ML-DSA-65/87 |
| DPoP proof | ES256 | ML-DSA-44 |
| TLS key exchange | X25519 (and X25519MLKEM768 by default on Go 1.27 peers) | X25519MLKEM768 required |
| Binding values | SHA-256 (`x5t#S256`, `jkt`, `ath`) | unchanged: SHA-256 is algorithm-agnostic |

### Endpoints added by this project

| Endpoint | Service | Purpose |
|---|---|---|
| `POST /v1/enroll?lifetime=` | ric-ca | first enrollment, authenticated by a one-time bootstrap certificate |
| `POST /v1/renew?lifetime=` | ric-ca | renewal or rotation, authenticated by the current certificate |
| `GET /v1/ca-chain` | ric-ca | issuing certificates |
| `POST /v1/upgrade` | pq-shim | exchange a classical token for an ML-DSA-signed, PQ-bound token |
| `GET /v1/jwks` | pq-shim | the shim AKP (ML-DSA) public key |
| `POST /v1/introspect` | pq-shim | RFC 7662 introspection for shim-issued tokens |
| `GET /api/v1/sdl/{key}` | demo xApps | protected resource, validated locally |
| `GET /api/v1/introspect/sdl/{key}` | demo xApps | protected resource, validated by introspection |
