# Token Ownership Zero-Knowledge Proof

This project demonstrates how to create a zero-knowledge proof of token ownership using SP1, a zkVM for Rust programs.

## Overview

The proof verifies the following without revealing which addresses you control:

1. **Signature Verification**: Proves control of Ethereum addresses via signatures
2. **Merkle Proof Verification**: Proves addresses are included in a Merkle tree
3. **Balance Summation**: Calculates total balance without revealing individual addresses

## How It Works

1. You provide signatures created with your Ethereum private keys
2. The program recovers Ethereum addresses from these signatures
3. It verifies these addresses are in a Merkle tree with specific balances
4. It sums the balances of all verified addresses

The only value made public is the total balance - all addresses and individual balances remain private.

## Prerequisites

- Rust and Cargo
- SP1 toolchain (install with `curl -L https://sp1up.succinct.xyz | bash && sp1up`)

## Project Structure

- `program/`: Contains the zkVM program that performs verification
- `script/`: Contains the code to generate and verify proofs
- `data/`: Contains input files:
  - `public_inputs.json`: Message digest and Merkle root
  - `private_inputs.json`: Signatures and Merkle proofs

## Getting Started

### Build the Program

```bash
cd program
cargo prove build
```

### Execute Without Proving (for testing)

This runs the program to verify it works correctly without generating a proof (much faster):

```bash
cd ../script
cargo run -- execute
```

### Generate a Proof

Generate a compressed proof (for off-chain verification):

```bash
cd ../script
cargo run -- prove
```

## Input File Format

### public_inputs.json

```json
{
  "message_digest": "0x48873dd6d52f2ff3feb97a4dfd14e63f620bcd84ed4fb67e930a8b86ad4c2b99",
  "merkle_root": "a9132fa40b9b025d030d315c02f63a559018c4da71617e5f5dfb1cf79605fab9"
}
```

### private_inputs.json

```json
{
  "signed_messages": [
    {
      "signature": "0x3c1ec93b0096ea6fc26230cb0ec4b3fd6450b301057a94684cd10c05b2bbf7ca7060b6b407a98d4e1231cb60bf6b6b4353199ca109ee246af10f30590917fc991b",
      "balance": 1000,
      "inclusion_branches": {
        "index": 0,
        "proof": [
          "c6bb9e5f764833a61ab94cc10b4b4b670de6080c490d6bd95f790f1c03561184",
          "c40a7dff609df43e7bd935e2d14d900f506fc334f7325fa5774dbdd1377e96a6",
          "c167a29b86b94a4aeb8aadfad4ae75120a0467631aceb6916ff615664f2c1522"
        ]
      }
    },
    {
      "signature": "0x1f90d45613de741cead148f5de7e242f7f9411a3d6a2decd40c144bd5b19e3232f529d39c4dae0360b029e4386026f47e7f5ab403c17c5e9a5eb43c8d3e508ba1c",
      "balance": 1500,
      "inclusion_branches": {
        "index": 3,
        "proof": [
          "907c75a61dbf259fcdd5b322d24eeb4c7d653d93bcd33a50d102b0787f0003ad",
          "8238cf2642076f8e643176273da958e2a4a7c0d1b392115ed6b8f69c5130410a",
          "c167a29b86b94a4aeb8aadfad4ae75120a0467631aceb6916ff615664f2c1522"
        ]
      }
    }
  ]
}
```

