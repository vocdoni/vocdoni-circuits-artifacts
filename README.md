# Vocdoni Circuit Artifacts

Welcome to the **Vocdoni Circuit Artifacts** repository! This repository houses the zkSNARK circuit artifacts essential for the new **Vocdoni DaVinci Protocol**. These artifacts are crucial for ensuring secure and efficient operations within the Vocdoni ecosystem.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Generating Artifacts](#generating-artifacts)
- [Artifacts](#artifacts)
- [References](#references)

## Overview

The **Vocdoni Circuit Artifacts** repository contains the generated zkSNARK circuit artifacts for the **Vote Verifier** and **Aggregator** components of the Vocdoni DaVinci Protocol. These artifacts are utilized by the Vocdoni Sequencer backend to validate and aggregate votes securely.

All artifact files and their corresponding SHA256 hash files are organized within the `./voteverifier` and `./aggregator` directories in the root folder.

## Prerequisites

Before generating the circuit artifacts, ensure you have the following installed on your system:

- **Go** (version 1.22 or later): [Download Go](https://golang.org/dl/)
- **GNARK Library**: A high-performance zkSNARK library for Go.
- **promptui**: A library for building interactive command-line prompts in Go.

## Installation

### Clone the Repository

```bash
git clone https://github.com/vocdoni/vocdoni-circuit-artifacts.git
cd vocdoni-circuit-artifacts
```

### Initialize Go Modules

Ensure you're within the project directory and initialize Go modules:

```bash
go mod tidy
```

### Build the CLI Tool

Compile the CLI tool to create an executable:

```bash
go build -o davinci-artifacts-cli
```

This command generates an executable named `davinci-artifacts-cli` in your current directory.

## Usage
The `davinci-artifacts-cli` tool facilitates the generation of zkSNARK circuit artifacts for the Vocdoni DaVinci Protocol. It offers an interactive menu for selecting the desired operation.

### Generating Artifacts
Run the CLI tool with the --destination flag to specify the output directory for the generated artifacts.

```bash
./davinci-artifacts-cli
```

Upon running, you'll encounter an interactive menu with the following options:

```bash
? Select an option › 
  ▸ Generate Vote Verifier Artifacts
    Generate Aggregator Artifacts
    Generate Both
    Exit
Use the up and down arrow keys to navigate through the options and press Enter to select.
```

#### Generate Vote Verifier Artifacts

1. **Select "Generate Vote Verifier Artifacts"**

2. **Provide Ballot Proof Verification Key Path:** You'll be prompted to enter the path to the Ballot Proof Verification Key. A default value is provided, which you can accept by pressing Enter or modify as needed.

```bash
    ? Enter Ballot Proof Verification Key path › ballotproof/ballot_proof_vkey.json
```

3. **Artifact Generation:** The tool will compile the Vote Verifier circuit, generate the necessary artifacts, compute their SHA256 hashes, and log these hashes into `voteverifier_hashes.txt` within the `./voteverifier` directory.

```bash
    Vote Verifier circuit compiled successfully.
    voteverifier.ccs hash: <hash_value>
    voteverifier.pk hash: <hash_value>
    voteverifier.vk hash: <hash_value>
    Vote Verifier hashes logged successfully in ./voteverifier/voteverifier_hashes.txt
```

#### Generate Aggregator Artifacts

1. **Select "Generate Aggregator Artifacts"**
2. **Artifact Generation:** The tool ensures that Vote Verifier artifacts exist before proceeding. It then compiles the Aggregator circuit, generates the necessary artifacts, computes their SHA256 hashes, and logs these hashes into `aggregator_hashes.txt` within the `./aggregator` directory.

```bash
    Aggregator circuit compiled successfully.
    aggregator.ccs hash: <hash_value>
    dummy.ccs hash: <hash_value>
    dummy.pk hash: <hash_value>
    aggregator.pk hash: <hash_value>
    aggregator.vk hash: <hash_value>
    Aggregator hashes logged successfully in ./aggregator/aggregator_hashes.txt
```

#### Generate Both Artifacts
1. **Select "Generate Both"**
2. **Sequential Artifact Generation:** The tool will sequentially generate artifacts for both Vote Verifier and Aggregator, along with their respective hash log files.

```bash
    Vote Verifier circuit compiled successfully.
    voteverifier.ccs hash: <hash_value>
    voteverifier.pk hash: <hash_value>
    voteverifier.vk hash: <hash_value>
    Vote Verifier hashes logged successfully in ./voteverifier/voteverifier_hashes.txt

    Aggregator circuit compiled successfully.
    aggregator.ccs hash: <hash_value>
    dummy.ccs hash: <hash_value>
    dummy.pk hash: <hash_value>
    aggregator.pk hash: <hash_value>
    aggregator.vk hash: <hash_value>
    Aggregator hashes logged successfully in ./aggregator/aggregator_hashes.txt
```

## Artifacts
All generated artifacts and their corresponding hash files are stored within the [`./voteverifier`](./voteverifier) directory. Below is an overview of the included files:

### Vote Verifier Artifacts
 - [`voteverifier.ccs`](./voteverifier/voteverifier.ccs): Constraint System file.
 - [`voteverifier.pk`](./voteverifier/voteverifier.pk): Proving Key.
 - [`voteverifier.vk`](./voteverifier/voteverifier.vk): Verifying Key.
 - [`voteverifier_hashes.txt`](./voteverifier/voteverifier_hashes.txt): SHA256 hashes of the above artifacts.

### Aggregator Artifacts
 - [`aggregator.ccs`](./aggregator/aggregator.ccs): Constraint System file.
 - [`dummy.ccs`](./aggregator/dummy.ccs): Dummy Constraint System file.
 - [`dummy.pk`](./aggregator/dummy.pk): Dummy Proving Key.
 - [`aggregator.pk`](./aggregator/aggregator.pk): Proving Key.
 - [`aggregator.vk`](./aggregator/aggregator.vk): Verifying Key.
 - [`aggregator_hashes.txt`](./aggregator/aggregator_hashes.txt): SHA256 hashes of the above artifacts.

## References
 - DaVinci Sequencer Repository: [vocdoni-sequencer](https://github.com/vocdoni/vocdoni-sequencer) - This repository utilizes the artifacts generated in this repository to validate and aggregate votes within the Vocdoni DaVinci Protocol.

 - Circom Circuits Repository: [z-ircuits](https://github.com/vocdoni/z-ircuits) - Contains the Circom circuits for generating the Ballot Proof used by the Vote Verifier.