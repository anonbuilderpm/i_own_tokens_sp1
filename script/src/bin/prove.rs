use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sp1_sdk::{ProverClient, SP1Stdin, utils, SP1ProofWithPublicValues};
use std::fs;
use std::path::PathBuf;

// Public inputs structure
#[derive(Deserialize, Serialize, Debug)]
struct PublicInputs {
    message_digest: String,
    merkle_root: String,
}

// Structure for inclusion branches in Merkle proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InclusionBranches {
    pub index: u32,
    pub proof: Vec<String>,
}

// Structure for a single address claim - without the address field
#[derive(Debug, Serialize, Deserialize)]
struct SignedMessage {
    signature: String,
    balance: u64,
    inclusion_branches: InclusionBranches,
}

// Private inputs structure
#[derive(Debug, Serialize, Deserialize)]
struct PrivateInputs {
    signed_messages: Vec<SignedMessage>,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute the program without generating a proof
    Execute {
        #[arg(short = 'u', long, default_value = "../data_1/public_inputs.json")]
        public_file: PathBuf,
        
        #[arg(short = 'r', long, default_value = "../data_1/private_inputs.json")]
        private_file: PathBuf,
    },
    /// Generate a proof of token ownership
    Prove {
        #[arg(short = 'u', long, default_value = "../data_1/public_inputs.json")]
        public_file: PathBuf,
        
        #[arg(short = 'r', long, default_value = "../data_1/private_inputs.json")]
        private_file: PathBuf,
        
        /// Output file for the binary proof data
        #[arg(short, long, default_value = "proof.bin")]
        output: PathBuf,
        
        #[arg(short, long)]
        groth16: bool,
    },
    /// Verify a previously generated proof
    Verify {
        /// Path to the binary proof file generated with the 'prove' command
        #[arg(short, long)]
        proof_file: PathBuf,
        
        #[arg(short = 'u', long, default_value = "../data_1/public_inputs.json")]
        public_file: PathBuf,
    },
    /// Inspect the public values in a proof without verification
    Inspect {
        /// Path to the binary proof file to inspect
        #[arg(short, long)]
        proof_file: PathBuf,
    },
}

fn main() {
    // Setup logging
    utils::setup_logger();
    
    let cli = Cli::parse();
    
    match &cli.command {
        Commands::Execute { public_file, private_file } => {
            println!("Executing token ownership verification program...");
            
            // Get the ELF file
            let elf_path = std::env::var("SP1_ELF_token-ownership-program")
                .expect("ELF path not found. Did you run 'cargo prove build' in the program directory?");
            let elf = fs::read(elf_path).expect("Failed to read ELF file");
            
            // Create a ProverClient
            let client = ProverClient::from_env();
            
            // Read input files
            let public_inputs: PublicInputs = serde_json::from_str(
                &fs::read_to_string(public_file).expect("Failed to read public inputs")
            ).expect("Failed to parse public inputs");
            
            let private_inputs: PrivateInputs = serde_json::from_str(
                &fs::read_to_string(private_file).expect("Failed to read private inputs")
            ).expect("Failed to parse private inputs");
            
            println!("Public inputs: Message digest: {}, Merkle root: {}", 
                     public_inputs.message_digest, public_inputs.merkle_root);
            println!("Private inputs: {} signed messages", private_inputs.signed_messages.len());
            
            // Create program input
            let mut stdin = SP1Stdin::new();
            stdin.write(&public_inputs);
            stdin.write(&private_inputs);
            
            // Execute program
            let (mut public_values, execution_report) = client.execute(&elf, &stdin)
                .run()
                .expect("Execution failed");
            
            // Read public outputs (just the total balance)
            let total_balance: u64 = public_values.read();
            
            println!("\n=== Execution Results ===");
            println!("Verified Total Balance: {}", total_balance);
            println!("Cycles used: {}", execution_report.total_instruction_count());
        },
        Commands::Prove { public_file, private_file, output, groth16 } => {
            println!("Generating token ownership proof...");
            
            // Get the ELF file
            let elf_path = std::env::var("SP1_ELF_token-ownership-program")
                .expect("ELF path not found. Did you run 'cargo prove build' in the program directory?");
            let elf = fs::read(elf_path).expect("Failed to read ELF file");
            
            // Create a ProverClient
            let client = ProverClient::from_env();
            
            // Read input files
            let public_inputs: PublicInputs = serde_json::from_str(
                &fs::read_to_string(public_file).expect("Failed to read public inputs")
            ).expect("Failed to parse public inputs");
            
            let private_inputs: PrivateInputs = serde_json::from_str(
                &fs::read_to_string(private_file).expect("Failed to read private inputs")
            ).expect("Failed to parse private inputs");
            
            println!("Public inputs: Message digest: {}, Merkle root: {}", 
                     public_inputs.message_digest, public_inputs.merkle_root);
            println!("Private inputs: {} signed messages", private_inputs.signed_messages.len());
            
            // Create program input
            let mut stdin = SP1Stdin::new();
            stdin.write(&public_inputs);
            stdin.write(&private_inputs);
            
            // Setup proving and verification keys
            let (pk, vk) = client.setup(&elf);
            
            // Generate proof
            println!("Generating proof... (this may take a while)");
            let proof_builder = client.prove(&pk, &stdin);
            let proof = if *groth16 {
                proof_builder.groth16().run().expect("Failed to generate Groth16 proof")
            } else {
                proof_builder.compressed().run().expect("Failed to generate compressed proof")
            };
            
            // Read public outputs
            let mut public_values = proof.public_values.clone();
            let total_balance: u64 = public_values.read();
            
            // Verify the proof
            println!("Verifying proof...");
            client.verify(&proof, &vk).expect("Proof verification failed");
            
            // Save the proof (binary format, not human-readable)
            proof.save(output).expect("Failed to save proof");
            
            println!("\n=== Proof Successfully Generated and Verified ===");
            println!("Verified Total Balance: {}", total_balance);
            println!("Proof saved to: {} (binary file)", output.display());
            
            if *groth16 {
                println!("\nPublic values for on-chain verification:");
                println!("Public values: 0x{}", hex::encode(proof.public_values.to_vec()));
                println!("Proof: 0x{}", hex::encode(proof.bytes()));
            }
        },
        Commands::Verify { proof_file, public_file } => {
            println!("Verifying token ownership proof...");
            
            // Get the ELF file
            let elf_path = std::env::var("SP1_ELF_token-ownership-program")
                .expect("ELF path not found. Did you run 'cargo prove build' in the program directory?");
            let elf = fs::read(elf_path).expect("Failed to read ELF file");
            
            // Create a ProverClient
            let client = ProverClient::from_env();
            
            // Load the proof (binary format)
            let proof = SP1ProofWithPublicValues::load(proof_file).expect("Failed to load proof");
            
            // Read public inputs file (optional, just for display)
            let public_inputs: PublicInputs = serde_json::from_str(
                &fs::read_to_string(public_file).expect("Failed to read public inputs")
            ).expect("Failed to parse public inputs");
            
            println!("Public inputs: Message digest: {}, Merkle root: {}", 
                     public_inputs.message_digest, public_inputs.merkle_root);
            
            // Setup the verification key
            let (_, vk) = client.setup(&elf);
            
            // Verify the proof
            client.verify(&proof, &vk).expect("Proof verification failed");
            
            // Read public outputs
            let mut public_values = proof.public_values.clone();
            let total_balance: u64 = public_values.read();
            
            println!("\n=== Proof Successfully Verified ===");
            println!("Verified Total Balance: {}", total_balance);
        },
        Commands::Inspect { proof_file } => {
            println!("Inspecting proof public values...");
            
            // Load the proof (binary format)
            let proof = SP1ProofWithPublicValues::load(proof_file).expect("Failed to load proof");
            
            // Read public outputs
            let mut public_values = proof.public_values.clone();
            let total_balance: u64 = public_values.read();
            
            println!("\n=== Proof Public Values ===");
            println!("Total Balance: {}", total_balance);
            println!("Proof Size: {} bytes", proof.bytes().len());
            println!("Raw Public Values (hex): 0x{}", hex::encode(proof.public_values.to_vec()));
        },
    }
} 