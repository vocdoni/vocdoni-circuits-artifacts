package statetransition_test

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/rs/zerolog"
	"github.com/vocdoni/vocdoni-circuits-artifacts/statetransition"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/dummy"
)

func TestCompileWithDummy(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	ccs, _, vk, err := dummy.CompileAndSetup(
		dummy.PlaceholderWithConstraints(1),
		circuits.AggregatorCurve.ScalarField())
	if err != nil {
		panic(err)
	}

	if _, err := statetransition.Compile(ccs, vk); err != nil {
		panic(err)
	}
}

func TestCompileWithAggregator(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	dummyCCS, _, dummyVK, err := compileAndSetup(
		dummy.PlaceholderWithConstraints(1),
		circuits.VoteVerifierCurve.ScalarField())
	if err != nil {
		panic(err)
	}

	// fix the dummy vk
	recursiveDummyVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](dummyVK)
	if err != nil {
		panic(err)
	}
	// generate dummy proofs and witness to fill the placeholders
	proofPlaceholder := stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyCCS)
	// copy the placeholders up to the max number of votes
	proofs := [circuits.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	// var dummyEncryptedBallots [circuits.VotesPerBatch][circuits.FieldsPerBallot][2][2]frontend.Variable
	for i := 0; i < circuits.VotesPerBatch; i++ {
		proofs[i] = proofPlaceholder
	}

	agCCS, _, agVK, err := compileAndSetup(
		&aggregator.AggregatorCircuit{
			Proofs:               proofs,
			BaseVerificationKey:  recursiveDummyVk,
			DummyVerificationKey: recursiveDummyVk,
		}, circuits.AggregatorCurve.ScalarField())
	if err != nil {
		panic(err)
	}

	if _, err := statetransition.Compile(agCCS, agVK); err != nil {
		panic(err)
	}
}

func compileAndSetup(placeholder frontend.Circuit, field *big.Int) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, placeholder)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile error: %w", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup error: %w", err)
	}
	return ccs, pk, vk, nil
}
