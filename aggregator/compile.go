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
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
)

func Compile(innerCCS constraint.ConstraintSystem, innerVk groth16.VerifyingKey) (constraint.ConstraintSystem, constraint.ConstraintSystem, groth16.ProvingKey, error) {
	// fix the inner vk
	recursiveInnerVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVk)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert inner vk to fixed: %w", err)
	}
	// compile the dummy circuit
	dummyCCS, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, aggregator.DummyPlaceholder(innerCCS))
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
	pubInputsPlaceholder := stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](dummyCCS)
	// copy the placeholders up to the max number of votes
	proofs := [aggregator.MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	pubInputs := [aggregator.MaxVotes]stdgroth16.Witness[sw_bls12377.ScalarField]{}
	var dummyEncryptedBallots [aggregator.MaxVotes][aggregator.MaxFields][2][2]frontend.Variable
	for i := 0; i < aggregator.MaxVotes; i++ {
		proofs[i] = proofPlaceholder
		pubInputs[i] = pubInputsPlaceholder
		for j := 0; j < aggregator.MaxFields; j++ {
			dummyEncryptedBallots[i][j] = [2][2]frontend.Variable{
				{frontend.Variable(0), frontend.Variable(0)},
				{frontend.Variable(0), frontend.Variable(0)},
			}
		}
	}
	// compile the final circuit
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &aggregator.AggregatorCircuit{
		EncryptedBallots:   dummyEncryptedBallots,
		VerifyProofs:       proofs,
		VerifyPublicInputs: pubInputs,
		VerificationKeys: [2]stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
			recursiveDummyVk,
			recursiveInnerVk,
		},
	})
	return ccs, dummyCCS, dummyPk, err
}
