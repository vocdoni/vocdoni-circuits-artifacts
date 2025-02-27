package aggregator

import (
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
)

func Compile(innerCCS constraint.ConstraintSystem, innerVk groth16.VerifyingKey) (constraint.ConstraintSystem, error) {
	// fix the inner vk
	recursiveInnerVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert inner vk to fixed: %w", err)
	}
	// generate dummy proofs and witness to fill the placeholders
	proofPlaceholder := stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCCS)
	witnessPlaceholder := stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](innerCCS)
	// copy the placeholders up to the max number of votes
	proofs := [circuits.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	witnesses := [circuits.VotesPerBatch]stdgroth16.Witness[sw_bls12377.ScalarField]{}
	for i := 0; i < circuits.VotesPerBatch; i++ {
		proofs[i] = proofPlaceholder
		witnesses[i] = witnessPlaceholder
	}
	// compile the final circuit
	ccs, err := frontend.Compile(circuits.AggregatorCurve.ScalarField(), r1cs.NewBuilder, &aggregator.AggregatorCircuit{
		Proofs:          proofs,
		Witnesses:       witnesses,
		VerificationKey: recursiveInnerVk,
	})
	return ccs, err
}
