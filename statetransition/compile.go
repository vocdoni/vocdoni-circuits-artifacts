package statetransition

import (
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/statetransition"
)

func Compile(agCCS constraint.ConstraintSystem, agVK groth16.VerifyingKey) (constraint.ConstraintSystem, error) {
	// fix the inner vk
	agVkFixed, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](agVK)
	if err != nil {
		return nil, fmt.Errorf("failed to convert inner vk to fixed: %w", err)
	}
	// fill the placeholders
	agProofPlaceholder := stdgroth16.PlaceholderProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](agCCS)
	// compile the final circuit
	ccs, err := frontend.Compile(circuits.StateTransitionCurve.ScalarField(), r1cs.NewBuilder, &statetransition.Circuit{
		AggregatorProof: agProofPlaceholder,
		AggregatorVK:    agVkFixed,
	})
	return ccs, err
}
