package xappclient

import "testing"

// The PQ_ISSUER switch decides whether the shim is in the path. Getting it wrong must
// be a configuration error, never a silent downgrade to a classical token.
func TestPQIssuerValidation(t *testing.T) {
	base := Config{Method: MethodLongTerm, Rotation: RotateOnCertExpiry, CertLifetime: DefaultLifetime(MethodLongTerm)}

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"shim issuer needs the shim URL", func(c *Config) {
			c.PQEnabled, c.PQIssuer = true, PQIssuerShim
		}, true},
		{"shim issuer with the shim URL is accepted", func(c *Config) {
			c.PQEnabled, c.PQIssuer, c.PQShimURL = true, PQIssuerShim, "https://pq-shim.ricsec.svc.cluster.local:8443"
			c.PQKeyAlg = "ML-DSA-65"
		}, false},
		{"keycloak issuer needs no shim URL", func(c *Config) {
			c.PQEnabled, c.PQIssuer, c.PQKeyAlg = true, PQIssuerKeycloak, "ML-DSA-65"
		}, false},
		{"an unknown issuer is refused", func(c *Config) {
			c.PQEnabled, c.PQIssuer, c.PQKeyAlg = true, "duende", "ML-DSA-65"
		}, true},
		{"the issuer is irrelevant outside post-quantum mode", func(c *Config) {
			c.PQIssuer = ""
		}, false},
	}
	for _, tc := range cases {
		c := base
		tc.mutate(&c)
		err := c.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
