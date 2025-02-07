package dummy

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/dummy"
)

func Compile(innerCCS constraint.ConstraintSystem) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
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
	return dummyCCS, dummyPk, dummyVk, err
}
