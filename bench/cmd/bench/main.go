// Command bench measures the three binding methods against the deployed testbed and
// writes one CSV with a fixed schema and row order (so runs are comparable), plus a
// separate CSV describing the run environment.
//
// Per method: token request latency; resource request latency and throughput with
// local validation vs introspection; token and DPoP proof sizes. Method B additionally:
// RIC CA cost per rotation and rotations/hour for a set of certificate lifetimes.
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/config"
	"github.com/oran-ricsec/xapp-token-binding/internal/logx"
	"github.com/oran-ricsec/xapp-token-binding/internal/netx"
	"github.com/oran-ricsec/xapp-token-binding/internal/smo"
	xappclient "github.com/oran-ricsec/xapp-token-binding/xapp-client"
	xappresource "github.com/oran-ricsec/xapp-token-binding/xapp-resource"
)

var header = []string{"method", "metric", "variant", "unit", "samples", "p50", "p95", "p99", "mean", "min", "max", "value"}

type row struct {
	method, metric, variant, unit string
	samples                       []float64 // distribution metrics
	value                         *float64  // scalar metrics
}

func (r row) record() []string {
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', 3, 64) }
	out := []string{r.method, r.metric, r.variant, r.unit}
	if r.value != nil {
		return append(out, "1", "", "", "", "", "", "", f(*r.value))
	}
	s := slices.Clone(r.samples)
	slices.Sort(s)
	if len(s) == 0 {
		return append(out, "0", "", "", "", "", "", "", "")
	}
	var sum float64
	for _, v := range s {
		sum += v
	}
	return append(out, strconv.Itoa(len(s)), f(pct(s, 50)), f(pct(s, 95)), f(pct(s, 99)), f(sum/float64(len(s))), f(s[0]), f(s[len(s)-1]), "")
}

// pct is the nearest-rank percentile of sorted samples.
func pct(sorted []float64, p float64) float64 {
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	return sorted[max(0, min(rank-1, len(sorted)-1))]
}

func scalar(method, metric, variant, unit string, v float64) row {
	return row{method: method, metric: metric, variant: variant, unit: unit, value: &v}
}

type params struct {
	tokenN, resourceN, rotationN, warmup, concurrency int
	rpsDuration                                       time.Duration
	lifetimes                                         []time.Duration
	methods                                           []string
}

type bench struct {
	ctx         context.Context
	log         *slog.Logger
	base        xappclient.Config
	onboarding  *smo.Onboarding
	resourceURL string
	clientIDs   map[xappclient.Method]string
	lifetime    map[xappclient.Method]time.Duration
	p           params
	rows        []row
}

func main() {
	out := flag.String("out", "results/bench.csv", "results CSV")
	envOut := flag.String("env-out", "results/bench-env.csv", "run environment CSV")
	flag.Parse()

	b, err := setup()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(2)
	}
	started := time.Now().UTC()
	for _, m := range b.p.methods {
		if err := b.run(xappclient.Method(m)); err != nil {
			fmt.Fprintf(os.Stderr, "method %s: %v\n", m, err)
			os.Exit(1)
		}
	}
	if err := writeCSV(*out, b.rows); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := b.writeEnv(*envOut, started); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	fmt.Printf("wrote %s (%d rows) and %s\n", *out, len(b.rows), *envOut)
}

func setup() (*bench, error) {
	e := &config.Env{}
	b := &bench{ctx: context.Background(), log: logx.New("bench")}
	b.p = params{
		tokenN:      e.Int("BENCH_TOKEN_N", 100),
		resourceN:   e.Int("BENCH_RESOURCE_N", 300),
		rotationN:   e.Int("BENCH_ROTATION_N", 30),
		warmup:      e.Int("BENCH_WARMUP", 10),
		concurrency: e.Int("BENCH_CONCURRENCY", 4),
		rpsDuration: e.Dur("BENCH_RPS_DURATION", 10*time.Second),
		methods:     e.List("BENCH_METHODS", []string{"A", "B", "C"}),
	}
	for _, l := range e.List("BENCH_ROTATION_LIFETIMES", []string{"5m", "15m", "1h", "24h"}) {
		d, err := time.ParseDuration(l)
		if err != nil {
			e.Fail("BENCH_ROTATION_LIFETIMES: %v", err)
			continue
		}
		b.p.lifetimes = append(b.p.lifetimes, d)
	}
	b.resourceURL = strings.TrimRight(e.Req("RESOURCE_URL"), "/")
	b.clientIDs = map[xappclient.Method]string{
		xappclient.MethodLongTerm:  e.Req("LONGTERM_CLIENT_ID"),
		xappclient.MethodEphemeral: e.Req("EPHEMERAL_CLIENT_ID"),
		xappclient.MethodDPoP:      e.Req("DPOP_CLIENT_ID"),
	}
	b.lifetime = map[xappclient.Method]time.Duration{
		xappclient.MethodLongTerm:  e.Dur("LONGTERM_CERT_LIFETIME", 168*time.Hour),
		xappclient.MethodEphemeral: e.Dur("EPHEMERAL_CERT_LIFETIME", 15*time.Minute),
		xappclient.MethodDPoP:      e.Dur("LONGTERM_CERT_LIFETIME", 168*time.Hour),
	}
	b.base = xappclient.Config{
		TokenURL:    e.Req("KEYCLOAK_TOKEN_URL"),
		Scope:       e.Str("TOKEN_SCOPE", ""),
		TrustBundle: e.List("RIC_TRUST_BUNDLE", nil),
		CAURL:       e.Req("RIC_CA_URL"),
		KeyAlg:      "EC-P256",
		DPoPAlg:     e.Str("DPOP_ALG", "ES256"),
		Rotation:    xappclient.RotateOnCertExpiry,
		HTTPTimeout: 30 * time.Second,
	}
	onbCert, onbKey, org := e.Req("SMO_ONBOARDING_CERT"), e.Req("SMO_ONBOARDING_KEY"), e.Req("ORG")
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		e.Fail("DIAL_OVERRIDES: %v", err)
	}
	if err := e.Err(); err != nil {
		return nil, err
	}
	b.base.DialOverrides = overrides
	if b.onboarding, err = smo.LoadOnboarding(onbCert, onbKey, org); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *bench) newClient(m xappclient.Method) (xappclient.Client, error) {
	cfg := b.base
	cfg.Method, cfg.ClientID, cfg.CertLifetime = m, b.clientIDs[m], b.lifetime[m]
	boot, err := b.onboarding.IssueBootstrap(cfg.ClientID, nil, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	cfg.Bootstrap = boot
	c, err := xappclient.New(cfg, b.log)
	if err != nil {
		return nil, err
	}
	return c, c.Start(b.ctx)
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Nanoseconds()) / 1e6 }

func (b *bench) path(mode xappresource.Mode) string {
	if mode == xappresource.ModeIntrospection {
		return b.resourceURL + "/api/v1/introspect/sdl/bench"
	}
	return b.resourceURL + "/api/v1/sdl/bench"
}

func (b *bench) call(c xappclient.Client, url string) error {
	req, err := http.NewRequestWithContext(b.ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (b *bench) run(m xappclient.Method) error {
	ms := string(m)
	fmt.Printf("== Method %s (%s)\n", ms, b.clientIDs[m])
	c, err := b.newClient(m)
	if err != nil {
		return err
	}
	for i := 0; i < b.p.warmup; i++ {
		if _, err := c.IssueToken(b.ctx); err != nil {
			return fmt.Errorf("warmup token: %w", err)
		}
		if err := b.call(c, b.path(xappresource.ModeLocal)); err != nil {
			return fmt.Errorf("warmup resource call: %w", err)
		}
	}

	// Token request latency (issuance path only; no rotation).
	var lat []float64
	var tok *xappclient.Token
	for i := 0; i < b.p.tokenN; i++ {
		t := time.Now()
		if tok, err = c.IssueToken(b.ctx); err != nil {
			return err
		}
		lat = append(lat, msSince(t))
	}
	b.rows = append(b.rows, row{method: ms, metric: "token_request_latency", variant: "issue_only", unit: "ms", samples: lat})
	fmt.Printf("  token request p50 %.1f ms\n", pct(sorted(lat), 50))

	// Method B: key generation + CSR + RIC CA round trip per rotation, then token.
	if m == xappclient.MethodEphemeral {
		var keygen, ca, total, rotTok []float64
		for i := 0; i < b.p.rotationN; i++ {
			t := time.Now()
			st, err := c.Rotate(b.ctx)
			if err != nil {
				return err
			}
			if _, err := c.IssueToken(b.ctx); err != nil {
				return err
			}
			rotTok = append(rotTok, msSince(t))
			keygen = append(keygen, float64(st.KeyGen.Nanoseconds())/1e6)
			ca = append(ca, float64(st.RoundTrip.Nanoseconds())/1e6)
			total = append(total, float64(st.Total.Nanoseconds())/1e6)
		}
		b.rows = append(b.rows,
			row{method: ms, metric: "token_request_latency", variant: "rotate_then_issue", unit: "ms", samples: rotTok},
			row{method: ms, metric: "rotation_keygen_latency", variant: "EC-P256", unit: "ms", samples: keygen},
			row{method: ms, metric: "rotation_ca_roundtrip_latency", variant: "csr_to_certificate", unit: "ms", samples: ca},
			row{method: ms, metric: "rotation_total_latency", variant: "keygen_plus_ca", unit: "ms", samples: total},
		)
		mean := meanOf(total)
		for _, l := range b.p.lifetimes {
			renewEvery := l - l/5 // default policy renews with 20% of the lifetime remaining
			perHour := float64(time.Hour) / float64(renewEvery)
			b.rows = append(b.rows,
				scalar(ms, "rotations_per_hour", "cert_lifetime="+l.String(), "count", perHour),
				scalar(ms, "rotation_ca_cost_per_hour", "cert_lifetime="+l.String(), "ms", perHour*mean))
		}
		fmt.Printf("  rotation total p50 %.1f ms (CA round trip p50 %.1f ms)\n", pct(sorted(total), 50), pct(sorted(ca), 50))
		if tok, err = c.Token(b.ctx); err != nil {
			return err
		}
	}

	// Sizes.
	b.rows = append(b.rows, scalar(ms, "access_token_size", tok.Binding, "bytes", float64(len(tok.Value))))
	if d, ok := c.(xappclient.DPoP); ok {
		tp, err := d.Proof(http.MethodPost, b.base.TokenURL, "")
		if err != nil {
			return err
		}
		rp, err := d.Proof(http.MethodGet, b.path(xappresource.ModeLocal), tok.Value)
		if err != nil {
			return err
		}
		b.rows = append(b.rows,
			scalar(ms, "dpop_proof_size", "token_request", "bytes", float64(len(tp))),
			scalar(ms, "dpop_proof_size", "resource_request_with_ath", "bytes", float64(len(rp))))
	}

	// Resource request latency and throughput: local validation vs introspection.
	for _, mode := range []xappresource.Mode{xappresource.ModeLocal, xappresource.ModeIntrospection} {
		var rl []float64
		for i := 0; i < b.p.resourceN; i++ {
			t := time.Now()
			if err := b.call(c, b.path(mode)); err != nil {
				return fmt.Errorf("resource %s: %w", mode, err)
			}
			rl = append(rl, msSince(t))
		}
		b.rows = append(b.rows, row{method: ms, metric: "resource_request_latency", variant: string(mode), unit: "ms", samples: rl})
		rps, errs := b.throughput(c, b.path(mode))
		b.rows = append(b.rows,
			scalar(ms, "resource_throughput", string(mode), "req/s", rps),
			scalar(ms, "resource_errors_during_throughput", string(mode), "count", float64(errs)))
		fmt.Printf("  resource %-13s p50 %.1f ms, %.1f req/s (%d errors)\n", mode, pct(sorted(rl), 50), rps, errs)
	}
	return nil
}

func (b *bench) throughput(c xappclient.Client, url string) (float64, int64) {
	var ok, failed atomic.Int64
	deadline := time.Now().Add(b.p.rpsDuration)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < b.p.concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if err := b.call(c, url); err != nil {
					failed.Add(1)
				} else {
					ok.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	return float64(ok.Load()) / time.Since(start).Seconds(), failed.Load()
}

func sorted(v []float64) []float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	return s
}

func meanOf(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func writeCSV(path string, rows []row) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write(header)
	for _, r := range rows {
		_ = w.Write(r.record())
	}
	w.Flush()
	return w.Error()
}

func (b *bench) writeEnv(path string, started time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	host, _ := os.Hostname()
	lifetimes := make([]string, len(b.p.lifetimes))
	for i, l := range b.p.lifetimes {
		lifetimes[i] = l.String()
	}
	w := csv.NewWriter(f)
	for _, kv := range [][2]string{
		{"started_utc", started.Format(time.RFC3339)},
		{"finished_utc", time.Now().UTC().Format(time.RFC3339)},
		{"host", host},
		{"go_version", runtime.Version()},
		{"cpus", strconv.Itoa(runtime.NumCPU())},
		{"methods", strings.Join(b.p.methods, " ")},
		{"token_samples", strconv.Itoa(b.p.tokenN)},
		{"resource_samples", strconv.Itoa(b.p.resourceN)},
		{"rotation_samples", strconv.Itoa(b.p.rotationN)},
		{"warmup", strconv.Itoa(b.p.warmup)},
		{"throughput_concurrency", strconv.Itoa(b.p.concurrency)},
		{"throughput_duration", b.p.rpsDuration.String()},
		{"rotation_lifetimes", strings.Join(lifetimes, " ")},
		{"renewal_policy", "renew with 20% of certificate lifetime remaining"},
		{"token_url", b.base.TokenURL},
		{"resource_url", b.resourceURL},
		{"dpop_alg", b.base.DPoPAlg},
		{"identity_key_alg", b.base.KeyAlg},
	} {
		_ = w.Write(kv[:])
	}
	w.Flush()
	return w.Error()
}
