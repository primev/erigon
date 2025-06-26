// core/vm/precompile_bls_verify.go
// Copyright 2024 The Erigon Authors
//
// This file is part of Erigon.
// Licensed under the GNU Lesser General Public License v3.0; see LICENSE for details.

package vm

import (
	"github.com/cloudflare/circl/sign/bls"
	"math/big"
)

type blsVerifyPrecompile struct{}

// RequiredGas meters the VERIFY operation. Tune these values per the EIP-2537 spec.
func (p *blsVerifyPrecompile) RequiredGas(input []byte) uint64 {
	const base = 50_000
	const perByte = 5
	return base + perByte*uint64(len(input))
}

// Run(input) executes a BLS signature verify precompile. The VM will
// deduct RequiredGas(input) before calling this. Return is a 32-byte
// big-endian boolean word (1 for success, 0 for failure).
func (p *blsVerifyPrecompile) Run(input []byte) ([]byte, error) {
	const pubKeyLen = 48
	const sigLen = 96

	// If there's not enough data for pubkey+sig, return false (no revert).
	if len(input) < pubKeyLen+sigLen {
		return make([]byte, 32), nil
	}
	pubBytes := input[:pubKeyLen]
	sigBytes := input[pubKeyLen : pubKeyLen+sigLen]
	msg := input[pubKeyLen+sigLen:]

	// Unmarshal the G1 public key.
	pub := new(bls.PublicKey[bls.G1])
	if err := pub.UnmarshalBinary(pubBytes); err != nil {
		return make([]byte, 32), nil
	}

	// Perform the BLS verify.
	ok := bls.Verify[bls.G1](pub, msg, sigBytes)

	// Encode the boolean result as a 32-byte big-endian integer.
	out := make([]byte, 32)
	if ok {
		big.NewInt(1).FillBytes(out)
	}
	return out, nil
}
