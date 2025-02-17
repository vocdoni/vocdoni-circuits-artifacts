package voteverifier

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
)

func Compile(ballotProofVKey []byte) (constraint.ConstraintSystem, error) {
	// generate the placeholders for the recursion
	placeholders, err := circuits.Circom2GnarkPlaceholder(ballotProofVKey)
	if err != nil {
		return nil, err
	}
	// compile the circuit
	return frontend.Compile(circuits.VoteVerifierCurve.ScalarField(), r1cs.NewBuilder, &voteverifier.VerifyVoteCircuit{
		CircomVerificationKey: placeholders.Vk,
		CircomProof:           placeholders.Proof,
	})
}
