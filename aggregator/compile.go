package aggregator

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/dummy"
)

func Compile(innerCCS constraint.ConstraintSystem, innerVk groth16.VerifyingKey) (constraint.ConstraintSystem, constraint.ConstraintSystem, groth16.ProvingKey, error) {
	// fix the inner vk
	recursiveInnerVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVk)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert inner vk to fixed: %w", err)
	}
	// compile the dummy circuit
	dummyCCS, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, dummy.Placeholder(innerCCS))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compile dummy circuit: %w", err)
	}
	// setup the dummy circuit
	dummyPk, dummyVk, err := groth16.Setup(dummyCCS)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to setup dummy circuit: %w", err)
	}
	// fix the dummy vk
	recursiveDummyVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](dummyVk)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert dummy vk to fixed: %w", err)
	}
	// generate dummy proofs and witness to fill the placeholders
	proofPlaceholder := stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyCCS)
	// copy the placeholders up to the max number of votes
	proofs := [circuits.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	// var dummyEncryptedBallots [circuits.VotesPerBatch][circuits.FieldsPerBallot][2][2]frontend.Variable
	for i := 0; i < circuits.VotesPerBatch; i++ {
		proofs[i] = proofPlaceholder
		// for j := 0; j < circuits.FieldsPerBallot; j++ {
		// 	dummyEncryptedBallots[i][j] = [2][2]frontend.Variable{
		// 		{frontend.Variable(0), frontend.Variable(1)},
		// 		{frontend.Variable(0), frontend.Variable(1)},
		// 	}
		// }
	}
	// compile the final circuit
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &aggregator.AggregatorCircuit{
		Proofs:               proofs,
		BaseVerificationKey:  recursiveInnerVk,
		DummyVerificationKey: recursiveDummyVk,
	})
	return ccs, dummyCCS, dummyPk, err
}
