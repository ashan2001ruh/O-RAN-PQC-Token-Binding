// Command smo-sim issues one-time bootstrap credentials from the simulated SMO onboarding CA.
//
//	smo-sim -cn xapp-longterm -dns xapp-a.ricxapp.svc.cluster.local,xapp-a.ricxapp.svc -out out/bootstrap/xapp-a
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oran-ricsec/xapp-token-binding/internal/pki"
	"github.com/oran-ricsec/xapp-token-binding/internal/smo"
)

func main() {
	cn := flag.String("cn", "", "xApp identity (certificate CN, must equal the Keycloak client id)")
	dns := flag.String("dns", "", "comma-separated DNS names granted to the xApp")
	out := flag.String("out", "", "output directory (tls.crt, tls.key)")
	caCert := flag.String("ca-cert", os.Getenv("SMO_ONBOARDING_CERT"), "onboarding CA certificate")
	caKey := flag.String("ca-key", os.Getenv("SMO_ONBOARDING_KEY"), "onboarding CA key")
	org := flag.String("org", os.Getenv("ORG"), "organization")
	validity := flag.Duration("validity", 24*time.Hour, "bootstrap certificate validity")
	keyAlg := flag.String("key-alg", "EC-P256", "bootstrap key algorithm (EC-P256, ML-DSA-44/65/87)")
	flag.Parse()
	if *cn == "" || *out == "" || *caCert == "" || *caKey == "" {
		flag.Usage()
		os.Exit(2)
	}
	ob, err := smo.LoadOnboarding(*caCert, *caKey, *org)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load onboarding CA:", err)
		os.Exit(1)
	}
	var names []string
	for _, n := range strings.Split(*dns, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	ob.KeyAlg = *keyAlg
	cred, err := ob.IssueBootstrap(*cn, names, *validity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "issue:", err)
		os.Exit(1)
	}
	if err := smo.WriteCredential(*out, cred); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("bootstrap credential for %s (%s, serial %s, expires %s) written to %s\n",
		*cn, pki.KeyAlgName(cred.Leaf.PublicKey), cred.Leaf.SerialNumber.Text(16),
		cred.Leaf.NotAfter.UTC().Format(time.RFC3339), *out)
}
