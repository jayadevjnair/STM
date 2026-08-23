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
},

    /// Inspect an STM container
    Inspect {
        /// STM container file
        input: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
Commands::Create {
    output,
    count,
    signed,
} => {            
    use stm_core::ObjectFlags;
            use stm_writer::ContainerBuilder;

            let mut builder = ContainerBuilder::new();

            for i in 0..count {
                let mut oid = [0u8; 16];

                // Deterministic OID for testing.
                oid[8..16].copy_from_slice(&(i as u64).to_be_bytes());

                let payload = format!("Object number {}", i).into_bytes();

                builder.add_object(
                    oid,
                    0x0001,
                    ObjectFlags(0),
                    payload,
                )?;
            }

let data = if signed {
    builder.build_signed()?
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

            // Read the complete STM container.
            let data = std::fs::read(&input)?;

            // Parse and strictly validate it.
            let parser = StmParser::new(ParserMode::Strict);
            let summary = parser.parse_bytes(&data)?;

            println!("STM Container Inspection");
            println!("File: {}", input.display());
            println!("Version: 1.0");
            println!("Total Length: {} bytes", summary.total_length);
            println!("Objects: {}", summary.object_count);
            println!(
    "Signed: {}",
    if summary.signed { "YES" } else { "NO" }
);

if let Some(valid) = summary.signature_valid {
    println!(
        "Signature: {}",
        if valid { "VALID" } else { "INVALID" }
    );
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
    }

    Ok(())
}