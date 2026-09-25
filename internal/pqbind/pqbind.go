// Package pqbind holds the constants shared by the post-quantum binding-transfer
// proof: the client builds it, the shim verifies it.
package pqbind

// ProofHeader carries the post-quantum binding proof on the upgrade request.
const ProofHeader = "X-PQ-Proof"

// ProofType is the "typ" of that proof JWT.
const ProofType = "pq-binding+jwt"
