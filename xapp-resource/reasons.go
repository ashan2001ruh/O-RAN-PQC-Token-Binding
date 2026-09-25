package xappresource

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Rejection reason codes. Each rejection carries one code plus a human-readable detail.
const (
	ReasonAuthorizationMissing   = "authorization_missing"
	ReasonAuthorizationMalformed = "authorization_malformed"
	ReasonSchemeUnsupported      = "authorization_scheme_unsupported"

	ReasonTokenMalformed        = "token_malformed"
	ReasonTokenKeyUnavailable   = "token_key_unavailable"
	ReasonTokenSignatureInvalid = "token_signature_invalid"
	ReasonTokenExpired          = "token_expired"
	ReasonTokenNotYetValid      = "token_not_yet_valid"
	ReasonTokenIssuerMismatch   = "token_issuer_mismatch"
	ReasonTokenAudienceMismatch = "token_audience_mismatch"
	ReasonTokenInactive         = "token_inactive"
	ReasonIntrospectionFailed   = "introspection_failed"
	ReasonInsufficientScope     = "insufficient_scope"

	ReasonCnfMissing      = "cnf_missing"
	ReasonCnfMalformed    = "cnf_malformed"
	ReasonCnfUnrecognized = "cnf_unrecognized"

	ReasonClientCertMissing    = "client_certificate_missing"
	ReasonClientCertExpired    = "client_certificate_expired"
	ReasonClientCertInvalid    = "client_certificate_invalid"
	ReasonX5tMismatch          = "cnf_x5t_mismatch"
	ReasonCertBoundWrongScheme = "cert_bound_token_wrong_scheme"

	ReasonDPoPAsBearer        = "dpop_token_used_as_bearer"
	ReasonDPoPProofMissing    = "dpop_proof_missing"
	ReasonDPoPProofMultiple   = "dpop_proof_multiple"
	ReasonDPoPProofMalformed  = "dpop_proof_malformed"
	ReasonDPoPProofType       = "dpop_proof_wrong_typ"
	ReasonDPoPProofAlg        = "dpop_proof_alg_not_allowed"
	ReasonDPoPProofJWK        = "dpop_proof_jwk_invalid"
	ReasonDPoPProofSignature  = "dpop_proof_signature_invalid"
	ReasonDPoPJktMismatch     = "dpop_jkt_mismatch"
	ReasonDPoPAthMissing      = "dpop_ath_missing"
	ReasonDPoPAthMismatch     = "dpop_ath_mismatch"
	ReasonDPoPHtmMismatch     = "dpop_htm_mismatch"
	ReasonDPoPHtuMismatch     = "dpop_htu_mismatch"
	ReasonDPoPIatOutOfWindow  = "dpop_iat_out_of_window"
	ReasonDPoPJtiMissing      = "dpop_jti_missing"
	ReasonDPoPReplayed        = "dpop_proof_replayed"
	ReasonDPoPReplayCacheFull = "dpop_replay_cache_full"
)

// Rejection is a fail-closed authorization decision.
type Rejection struct {
	Status int
	Code   string
	Detail string
	DPoP   bool // challenge with the DPoP scheme
}

func (r *Rejection) Error() string { return r.Code + ": " + r.Detail }

func reject(code, format string, args ...any) *Rejection {
	status := http.StatusUnauthorized
	if code == ReasonInsufficientScope {
		status = http.StatusForbidden
	}
	return &Rejection{Status: status, Code: code, Detail: fmt.Sprintf(format, args...), DPoP: strings.HasPrefix(code, "dpop_")}
}

// RejectionBody is the JSON body returned with every rejection.
type RejectionBody struct {
	Error      string `json:"error"`
	ReasonCode string `json:"reason_code"`
	Reason     string `json:"reason"`
}

func writeRejection(w http.ResponseWriter, r *Rejection) {
	errCode := "invalid_token"
	switch {
	case r.Code == ReasonInsufficientScope:
		errCode = "insufficient_scope"
	case strings.HasPrefix(r.Code, "dpop_proof") || r.Code == ReasonDPoPJktMismatch || strings.HasPrefix(r.Code, "dpop_ath") ||
		r.Code == ReasonDPoPHtmMismatch || r.Code == ReasonDPoPHtuMismatch || r.Code == ReasonDPoPIatOutOfWindow || r.Code == ReasonDPoPJtiMissing:
		errCode = "invalid_dpop_proof"
	}
	scheme := "Bearer"
	if r.DPoP {
		scheme = "DPoP"
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`%s error=%q, error_description=%q`, scheme, errCode, r.Code))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(r.Status)
	_ = json.NewEncoder(w).Encode(RejectionBody{Error: errCode, ReasonCode: r.Code, Reason: r.Detail})
}
