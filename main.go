package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/manifoldco/promptui"
	"github.com/vocdoni/vocdoni-circuits-artifacts/aggregator"
	"github.com/vocdoni/vocdoni-circuits-artifacts/dummy"
	"github.com/vocdoni/vocdoni-circuits-artifacts/statetransition"
	"github.com/vocdoni/vocdoni-circuits-artifacts/voteverifier"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
)

const artifactBaseURL = "https://circuits.ams3.cdn.digitaloceanspaces.com/dev"

func main() {
	// Handle interrupt signals gracefully
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalChan
		fmt.Println("\nReceived an interrupt. Exiting...")
		os.Exit(0)
	}()

	// Define fixed directories for artifacts
	voteVerifierDest := filepath.Join("voteverifier")
	dummyDest := filepath.Join("dummy")
	aggregatorDest := filepath.Join("aggregator")
	statetransitionDest := filepath.Join("statetransition")

	// Create artifact directories if they don't exist
	dirs := []string{voteVerifierDest, aggregatorDest, statetransitionDest}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			log.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	for {
		// Display interactive menu using promptui.Select
		prompt := promptui.Select{
			Label: "Select an option",
			Items: []string{
				"Generate Vote Verifier Artifacts",
				"Generate Dummy Vote Verifier Artifacts",
				"Generate Aggregator Artifacts",
				"Generate StateTransition Artifacts",
				"Generate All",
				"Exit",
			},
		}

		_, result, err := prompt.Run()
		if err != nil {
			log.Printf("Prompt failed: %v\n", err)
			continue
		}

		switch result {
		case "Generate Vote Verifier Artifacts":
			if err := generateVoteVerifierArtifacts(voteVerifierDest); err != nil {
				log.Printf("Error generating Vote Verifier artifacts: %v", err)
			}
		case "Generate Dummy Vote Verifier Artifacts":
			if err := generateDummyArtifacts(dummyDest); err != nil {
				log.Printf("Error generating Dummy artifacts: %v", err)
			}
		case "Generate Aggregator Artifacts":
			if err := generateAggregatorArtifacts(aggregatorDest); err != nil {
				log.Printf("Error generating Aggregator artifacts: %v", err)
			}
		case "Generate StateTransition Artifacts":
			if err := generateStateTransitionArtifacts(statetransitionDest); err != nil {
				log.Printf("Error generating StateTransition artifacts: %v", err)
			}
		case "Generate All":
			if err := generateVoteVerifierArtifacts(voteVerifierDest); err != nil {
				log.Printf("Error generating Vote Verifier artifacts: %v", err)
				break
			}
			if err := generateDummyArtifacts(dummyDest); err != nil {
				log.Printf("Error generating Dummy artifacts: %v", err)
				break
			}
			if err := generateAggregatorArtifacts(aggregatorDest); err != nil {
				log.Printf("Error generating Aggregator artifacts: %v", err)
			}
			if err := generateStateTransitionArtifacts(statetransitionDest); err != nil {
				log.Printf("Error generating StateTransition artifacts: %v", err)
			}
		case "Exit":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid choice. Please select a valid option.")
		}
	}
}

// logHashes writes the filename-hash pairs to a specified hash log file.
func logHashes(hashFileName string, hashes map[string]string, destination string) error {
	// Define the path for the hash log file
	hashFilePath := filepath.Join(destination, hashFileName)

	// Create or truncate the hash log file
	file, err := os.Create(hashFilePath)
	if err != nil {
		return fmt.Errorf("failed to create hash log file %s: %w", hashFilePath, err)
	}
	defer file.Close()

	// Write each filename and its hash to the file
	for filename, hash := range hashes {
		line := fmt.Sprintf("%s/%s %s\n", artifactBaseURL, filename, hash)
		if _, err := file.WriteString(line); err != nil {
			return fmt.Errorf("failed to write to hash log file %s: %w", hashFilePath, err)
		}
	}

	return nil
}

// generateVoteVerifierArtifacts handles the generation of Vote Verifier artifacts
func generateVoteVerifierArtifacts(destination string) error {
	// Prompt for Ballot Proof Verification Key path using promptui.Prompt
	prompt := promptui.Prompt{
		Label:   "Enter Ballot Proof Verification Key path",
		Default: "ballotproof/ballot_proof_vkey.json",
		Validate: func(input string) error {
			input = strings.TrimSpace(input)
			if input == "" {
				return fmt.Errorf("path cannot be empty")
			}
			if _, err := os.Stat(input); os.IsNotExist(err) {
				return fmt.Errorf("file does not exist at path: %s", input)
			}
			return nil
		},
	}

	ballotVKeyInput, err := prompt.Run()
	if err != nil {
		return fmt.Errorf("failed to get ballot proof verification key path: %w", err)
	}
	ballotVKeyInput = strings.TrimSpace(ballotVKeyInput)
	if ballotVKeyInput == "" {
		ballotVKeyInput = "ballotproof/ballot_proof_vkey.json"
	}

	// Read ballot proof verification key
	bpVk, err := os.ReadFile(ballotVKeyInput)
	if err != nil {
		return fmt.Errorf("failed to read ballot proof verification key: %w", err)
	}

	// Compile Vote Verifier circuit
	vvCS, err := voteverifier.Compile(bpVk)
	if err != nil {
		return fmt.Errorf("compilation failed: %w", err)
	}
	fmt.Println("Vote Verifier circuit compiled successfully.")

	// Initialize a map to store hashes
	hashes := make(map[string]string)

	// Write Vote Verifier circuit constraints
	csHash, err := writeCS(vvCS, filepath.Join(destination, "voteverifier.ccs"))
	if err != nil {
		return fmt.Errorf("failed to write voteverifier.ccs: %w", err)
	}
	fmt.Printf("voteverifier.ccs hash: %s\n", csHash)
	hashes["voteverifier.ccs"] = csHash

	// Setup Vote Verifier circuit
	vvPk, vvVk, err := groth16.Setup(vvCS)
	if err != nil {
		return fmt.Errorf("Groth16 setup failed: %w", err)
	}

	// Write Proving Key
	vvPkHash, err := writePK(vvPk, filepath.Join(destination, "voteverifier.pk"))
	if err != nil {
		return fmt.Errorf("failed to write voteverifier.pk: %w", err)
	}
	fmt.Printf("voteverifier.pk hash: %s\n", vvPkHash)
	hashes["voteverifier.pk"] = vvPkHash

	// Write Verifying Key
	vvVkHash, err := writeVK(vvVk, filepath.Join(destination, "voteverifier.vk"))
	if err != nil {
		return fmt.Errorf("failed to write voteverifier.vk: %w", err)
	}
	fmt.Printf("voteverifier.vk hash: %s\n", vvVkHash)
	hashes["voteverifier.vk"] = vvVkHash

	// Log the hashes to a text file
	if err := logHashes("voteverifier_hashes.txt", hashes, destination); err != nil {
		return fmt.Errorf("failed to log Vote Verifier hashes: %w", err)
	}
	fmt.Printf("Vote Verifier hashes logged successfully in ./%s/voteverifier_hashes.txt\n", destination)

	return nil
}

// generateDummyArtifacts handles the generation of Dummy artifacts
func generateDummyArtifacts(destination string) error {
	// Check if Vote Verifier artifacts exist
	vvCSPath := filepath.Join("voteverifier", "voteverifier.ccs")
	vvVkPath := filepath.Join("voteverifier", "voteverifier.vk")

	if _, err := os.Stat(vvCSPath); os.IsNotExist(err) {
		return fmt.Errorf("voteverifier.ccs not found in voteverifier. Please generate Vote Verifier artifacts first")
	}
	if _, err := os.Stat(vvVkPath); os.IsNotExist(err) {
		return fmt.Errorf("voteverifier.vk not found in voteverifier. Please generate Vote Verifier artifacts first")
	}

	// Read Vote Verifier Constraint System
	vvCSFile, err := os.Open(vvCSPath)
	if err != nil {
		return fmt.Errorf("failed to open voteverifier.ccs: %w", err)
	}
	defer vvCSFile.Close()
	vvCS := groth16.NewCS(circuits.VoteVerifierCurve)
	if _, err := vvCS.ReadFrom(vvCSFile); err != nil {
		return fmt.Errorf("failed to read voteverifier.ccs: %w", err)
	}

	// Read Vote Verifier Verifying Key
	vvVkFile, err := os.Open(vvVkPath)
	if err != nil {
		return fmt.Errorf("failed to open voteverifier.vk: %w", err)
	}
	defer vvVkFile.Close()
	vvVk := groth16.NewVerifyingKey(circuits.VoteVerifierCurve)
	if _, err := vvVk.ReadFrom(vvVkFile); err != nil {
		return fmt.Errorf("failed to read voteverifier.vk: %w", err)
	}

	// Initialize a map to store hashes
	hashes := make(map[string]string)

	// Compile Dummy circuit
	dummyCS, dummyPk, dummyVk, err := dummy.Compile(vvCS)
	if err != nil {
		return fmt.Errorf("failed to compile dummy: %w", err)
	}

	// Write Dummy circuit constraints
	dummycsHash, err := writeCS(dummyCS, filepath.Join(destination, "dummy.ccs"))
	if err != nil {
		return fmt.Errorf("failed to write dummy.ccs: %w", err)
	}
	fmt.Printf("dummy.ccs hash: %s\n", dummycsHash)
	hashes["dummy.ccs"] = dummycsHash

	// Write Dummy Proving Key
	dummyPkHash, err := writePK(dummyPk, filepath.Join(destination, "dummy.pk"))
	if err != nil {
		return fmt.Errorf("failed to write dummy.pk: %w", err)
	}
	fmt.Printf("dummy.pk hash: %s\n", dummyPkHash)
	hashes["dummy.pk"] = dummyPkHash

	// Write Dummy Verifying Key
	dummyVkHash, err := writeVK(dummyVk, filepath.Join(destination, "dummy.vk"))
	if err != nil {
		return fmt.Errorf("failed to write dummy.vk: %w", err)
	}
	fmt.Printf("dummy.vk hash: %s\n", dummyVkHash)
	hashes["dummy.vk"] = dummyVkHash

	// Log the hashes to a text file
	if err := logHashes("dummy_hashes.txt", hashes, destination); err != nil {
		return fmt.Errorf("failed to log Dummy hashes: %w", err)
	}
	fmt.Printf("Dummy hashes logged successfully in ./%s/dummy_hashes.txt\n", destination)

	return nil
}

// generateAggregatorArtifacts handles the generation of Aggregator artifacts
func generateAggregatorArtifacts(destination string) error {
	// Check if Vote Verifier artifacts exist
	dummyCSPath := filepath.Join("dummy", "dummy.ccs")
	dummyVkPath := filepath.Join("dummy", "dummy.vk")
	vvVkPath := filepath.Join("voteverifier", "voteverifier.vk")

	if _, err := os.Stat(dummyCSPath); os.IsNotExist(err) {
		return fmt.Errorf("dummy.ccs not found in dummy. Please generate Vote Verifier artifacts first")
	}
	if _, err := os.Stat(dummyVkPath); os.IsNotExist(err) {
		return fmt.Errorf("dummy.vk not found in dummy. Please generate Vote Verifier artifacts first")
	}
	if _, err := os.Stat(vvVkPath); os.IsNotExist(err) {
		return fmt.Errorf("voteverifier.vk not found in voteverifier. Please generate Vote Verifier artifacts first")
	}

	// Read Dummy Constraint System
	dummyCSFile, err := os.Open(dummyCSPath)
	if err != nil {
		return fmt.Errorf("failed to open voteverifier.ccs: %w", err)
	}
	defer dummyCSFile.Close()

	dummyCS := groth16.NewCS(circuits.VoteVerifierCurve)
	if _, err := dummyCS.ReadFrom(dummyCSFile); err != nil {
		return fmt.Errorf("failed to read voteverifier.ccs: %w", err)
	}

	// Read Dummy Verifying Key
	dummyVkFile, err := os.Open(dummyVkPath)
	if err != nil {
		return fmt.Errorf("failed to open dummy.vk: %w", err)
	}
	defer dummyVkFile.Close()

	dummyVk := groth16.NewVerifyingKey(circuits.VoteVerifierCurve)
	if _, err := dummyVk.ReadFrom(dummyVkFile); err != nil {
		return fmt.Errorf("failed to read dummy.vk: %w", err)
	}

	// Read Vote Verifier Verifying Key
	vvVkFile, err := os.Open(vvVkPath)
	if err != nil {
		return fmt.Errorf("failed to open voteverifier.vk: %w", err)
	}
	defer vvVkFile.Close()

	vvVk := groth16.NewVerifyingKey(circuits.VoteVerifierCurve)
	if _, err := vvVk.ReadFrom(vvVkFile); err != nil {
		return fmt.Errorf("failed to read voteverifier.vk: %w", err)
	}

	// Compile Aggregator circuit
	aggCS, err := aggregator.Compile(dummyCS, dummyVk, vvVk)
	if err != nil {
		return fmt.Errorf("compilation failed: %w", err)
	}
	fmt.Println("Aggregator circuit compiled successfully.")

	// Initialize a map to store hashes
	hashes := make(map[string]string)

	// Write Aggregator circuit constraints
	aggcsHash, err := writeCS(aggCS, filepath.Join(destination, "aggregator.ccs"))
	if err != nil {
		return fmt.Errorf("failed to write aggregator.ccs: %w", err)
	}
	fmt.Printf("aggregator.ccs hash: %s\n", aggcsHash)
	hashes["aggregator.ccs"] = aggcsHash

	// Setup Aggregator circuit
	aggPk, aggVk, err := groth16.Setup(aggCS)
	if err != nil {
		return fmt.Errorf("Groth16 setup failed: %w", err)
	}

	// Write Aggregator Proving Key
	aggPkHash, err := writePK(aggPk, filepath.Join(destination, "aggregator.pk"))
	if err != nil {
		return fmt.Errorf("failed to write aggregator.pk: %w", err)
	}
	fmt.Printf("aggregator.pk hash: %s\n", aggPkHash)
	hashes["aggregator.pk"] = aggPkHash

	// Write Aggregator Verifying Key
	aggVkHash, err := writeVK(aggVk, filepath.Join(destination, "aggregator.vk"))
	if err != nil {
		return fmt.Errorf("failed to write aggregator.vk: %w", err)
	}
	fmt.Printf("aggregator.vk hash: %s\n", aggVkHash)
	hashes["aggregator.vk"] = aggVkHash

	// Log the hashes to a text file
	if err := logHashes("aggregator_hashes.txt", hashes, destination); err != nil {
		return fmt.Errorf("failed to log Aggregator hashes: %w", err)
	}
	fmt.Printf("Aggregator hashes logged successfully in ./%s/aggregator_hashes.txt\n", destination)

	return nil
}

// generateStateTransitionArtifacts handles the generation of StateTransition artifacts
func generateStateTransitionArtifacts(destination string) error {
	// Check if Aggregator artifacts exist
	agCSPath := filepath.Join("aggregator", "aggregator.ccs")
	agVkPath := filepath.Join("aggregator", "aggregator.vk")

	if _, err := os.Stat(agCSPath); os.IsNotExist(err) {
		return fmt.Errorf("aggregator.ccs not found in aggregator. Please generate Aggregator artifacts first")
	}
	if _, err := os.Stat(agVkPath); os.IsNotExist(err) {
		return fmt.Errorf("aggregator.vk not found in aggregator. Please generate Aggregator artifacts first")
	}

	// Read Aggregator Constraint System
	agCSFile, err := os.Open(agCSPath)
	if err != nil {
		return fmt.Errorf("failed to open aggregator.ccs: %w", err)
	}
	defer agCSFile.Close()

	agCS := groth16.NewCS(circuits.AggregatorCurve)
	if _, err := agCS.ReadFrom(agCSFile); err != nil {
		return fmt.Errorf("failed to read aggregator.ccs: %w", err)
	}

	// Read Aggregator Verifying Key
	agVkFile, err := os.Open(agVkPath)
	if err != nil {
		return fmt.Errorf("failed to open aggregator.vk: %w", err)
	}
	defer agVkFile.Close()

	agVk := groth16.NewVerifyingKey(circuits.AggregatorCurve)
	if _, err := agVk.ReadFrom(agVkFile); err != nil {
		return fmt.Errorf("failed to read aggregator.vk: %w", err)
	}

	// Compile StateTransition circuit
	stCCS, err := statetransition.Compile(agCS, agVk)
	if err != nil {
		return fmt.Errorf("compilation failed: %w", err)
	}
	fmt.Println("StateTransition circuit compiled successfully.")

	// Initialize a map to store hashes
	hashes := make(map[string]string)

	// Write StateTransition circuit constraints
	stCCSHash, err := writeCS(stCCS, filepath.Join(destination, "statetransition.ccs"))
	if err != nil {
		return fmt.Errorf("failed to write statetransition.ccs: %w", err)
	}
	fmt.Printf("statetransition.ccs hash: %s\n", stCCSHash)
	hashes["statetransition.ccs"] = stCCSHash

	// Setup StateTransition circuit
	stPk, agVk, err := groth16.Setup(stCCS)
	if err != nil {
		return fmt.Errorf("Groth16 setup failed: %w", err)
	}

	// Write StateTransition Proving Key
	stPkHash, err := writePK(stPk, filepath.Join(destination, "statetransition.pk"))
	if err != nil {
		return fmt.Errorf("failed to write statetransition.pk: %w", err)
	}
	fmt.Printf("statetransition.pk hash: %s\n", stPkHash)
	hashes["statetransition.pk"] = stPkHash

	// Write StateTransition Verifying Key
	stVkHash, err := writeVK(agVk, filepath.Join(destination, "statetransition.vk"))
	if err != nil {
		return fmt.Errorf("failed to write statetransition.vk: %w", err)
	}
	fmt.Printf("statetransition.vk hash: %s\n", stVkHash)
	hashes["statetransition.vk"] = stVkHash

	// Log the hashes to a text file
	if err := logHashes("statetransition_hashes.txt", hashes, destination); err != nil {
		return fmt.Errorf("failed to log StateTransition hashes: %w", err)
	}
	fmt.Printf("StateTransition hashes logged successfully in ./%s/statetransition_hashes.txt\n", destination)

	return nil
}

// writeCS writes the Constraint System to a file and returns its SHA256 hash
func writeCS(cs constraint.ConstraintSystem, to string) (string, error) {
	var buf bytes.Buffer
	if _, err := cs.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("failed to write ConstraintSystem to buffer: %w", err)
	}
	return write(buf, to)
}

// writePK writes the Proving Key to a file and returns its SHA256 hash
func writePK(pk groth16.ProvingKey, to string) (string, error) {
	var buf bytes.Buffer
	if _, err := pk.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("failed to write ProvingKey to buffer: %w", err)
	}
	return write(buf, to)
}

// writeVK writes the Verifying Key to a file and returns its SHA256 hash
func writeVK(vk groth16.VerifyingKey, to string) (string, error) {
	var buf bytes.Buffer
	if _, err := vk.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("failed to write VerifyingKey to buffer: %w", err)
	}
	return write(buf, to)
}

// write handles writing the buffer to a file and computing its SHA256 hash
func write(content bytes.Buffer, to string) (string, error) {
	// Calculate SHA256 hash
	hashFn := sha256.New()
	if _, err := hashFn.Write(content.Bytes()); err != nil {
		return "", fmt.Errorf("failed to compute SHA256 hash: %w", err)
	}
	hash := hex.EncodeToString(hashFn.Sum(nil))

	// Write to file
	if err := os.WriteFile(to, content.Bytes(), 0o644); err != nil {
		return "", fmt.Errorf("failed to write to file %s: %w", to, err)
	}

	return hash, nil
}
