use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "stm")]
#[command(version = "0.1.0")]
#[command(about = "Secure Transfer Manifest container tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new STM container
    Create {
        /// Output file path
        output: PathBuf,

        /// Number of dummy objects
        #[arg(short, long, default_value_t = 1)]
        count: usize,

        /// Create a digitally signed STM container
        #[arg(long)]
        signed: bool,

        /// Path to the Ed25519 private key
        #[arg(long)]
        key: Option<PathBuf>,
    },

    /// Inspect an STM container
    Inspect {
        /// STM container file
        input: PathBuf,
    },

    /// Verify STM container integrity and signature
    Verify {
        /// STM container file
        input: PathBuf,
    },

    /// Generate an Ed25519 key pair
    Keygen {
        /// Directory where keys will be saved
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create {
            output,
            count,
            signed,
            key,
        } => {
            use stm_core::ObjectFlags;
            use stm_writer::ContainerBuilder;

            let mut builder = ContainerBuilder::new();

            for i in 0..count {
                let mut oid = [0u8; 16];

                oid[8..16].copy_from_slice(&(i as u64).to_be_bytes());

                let payload = format!("Object number {}", i).into_bytes();

                builder.add_object(oid, 0x0001, ObjectFlags(0), payload)?;
            }

            let data = if signed {
                let key_path = key.ok_or_else(|| {
                    anyhow::anyhow!(
                        "A private key is required when using --signed. Use --key <path>"
                    )
                })?;

                let key_data = std::fs::read(&key_path)?;

                let signing_key = stm_signature::load_signing_key(&key_data)
                    .map_err(|error| anyhow::anyhow!("{}", error))?;

                builder.build_signed(&signing_key)?
            } else {
                builder.build()?
            };

            std::fs::write(&output, data)?;

            println!("Created STM container: {}", output.display());
            println!("Objects: {}", count);
            println!("Signed: {}", if signed { "YES" } else { "NO" });
        }

        Commands::Inspect { input } => {
            use stm_parser::{ParserMode, StmParser};

            let data = std::fs::read(&input)?;
            let parser = StmParser::new(ParserMode::Strict);
            let summary = parser.parse_bytes(&data)?;

            println!("STM Container Inspection");
            println!("File: {}", input.display());
            println!("Version: 1.0");
            println!("Total Length: {} bytes", summary.total_length);
            println!("Objects: {}", summary.object_count);
            println!("Signed: {}", if summary.signed { "YES" } else { "NO" });

            if let Some(valid) = summary.signature_valid {
                println!("Signature: {}", if valid { "VALID" } else { "INVALID" });
            }

            println!("Merkle Root: {:02x?}", summary.merkle_root);

            println!(
                "Merkle: {}",
                if summary.merkle_valid {
                    "VALID"
                } else {
                    "INVALID"
                }
            );

            println!("State: VALID");
        }

        Commands::Verify { input } => {
            use stm_parser::{ParserMode, StmParser};

            let data = std::fs::read(&input)?;
            let parser = StmParser::new(ParserMode::Strict);

            match parser.parse_bytes(&data) {
                Ok(summary) => {
                    println!("STM Container Verification");
                    println!("File: {}", input.display());

                    println!(
                        "Merkle Integrity: {}",
                        if summary.merkle_valid {
                            "VALID"
                        } else {
                            "INVALID"
                        }
                    );

                    println!("Signed: {}", if summary.signed { "YES" } else { "NO" });

                    if let Some(valid) = summary.signature_valid {
                        println!(
                            "Digital Signature: {}",
                            if valid { "VALID" } else { "INVALID" }
                        );

                        if !valid {
                            println!("Result: INVALID");
                            println!("Reason: Digital signature verification failed");
                            std::process::exit(1);
                        }
                    } else {
                        println!("Digital Signature: NOT PRESENT");
                    }

                    println!("Result: VALID");
                }

                Err(error) => {
                    println!("STM Container Verification");
                    println!("File: {}", input.display());
                    println!("Result: INVALID");
                    println!("Reason: {}", error);

                    std::process::exit(1);
                }
            }
        }

        Commands::Keygen { output } => {
            use stm_signature::{generate_signing_key, public_key_bytes};

            std::fs::create_dir_all(&output)?;

            let signing_key = generate_signing_key();

            let private_key = signing_key.to_bytes();
            let public_key = public_key_bytes(&signing_key);

            let private_path = output.join("private.key");
            let public_path = output.join("public.key");

            std::fs::write(&private_path, private_key)?;
            std::fs::write(&public_path, public_key)?;

            println!("Ed25519 key pair generated");
            println!("Private key: {}", private_path.display());
            println!("Public key: {}", public_path.display());
        }
    }

    Ok(())
}
