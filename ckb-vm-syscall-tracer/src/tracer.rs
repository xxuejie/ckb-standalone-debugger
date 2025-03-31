use ckb_mock_tx_types::ReprMockTransaction;
use ckb_script::ScriptGroupType;
use ckb_types::{packed::Byte32, prelude::*};
use ckb_vm_syscall_tracer::{
    BinaryLocatorCollector, Collector, CollectorKind, CollectorResult, SyscallBasedCollector, TxPartsBasedCollector,
};
use clap::{Parser, ValueEnum};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum GroupKind {
    Lock,
    Type,
}

impl From<GroupKind> for ScriptGroupType {
    fn from(k: GroupKind) -> ScriptGroupType {
        match k {
            GroupKind::Lock => ScriptGroupType::Lock,
            GroupKind::Type => ScriptGroupType::Type,
        }
    }
}

fn parse_byte32(s: &str) -> Result<Byte32, String> {
    let offset = if s.starts_with("0x") { 2 } else { 0 };
    Byte32::from_slice(&hex::decode(&s[offset..]).map_err(|e| format!("Hex decoding error: {}", e))?)
        .map_err(|e| format!("Byte32 creation error: {}", e))
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Collector to use
    #[arg(long, value_enum, default_value_t = CollectorKind::Syscall)]
    collector: CollectorKind,

    /// Input mock tx file
    #[arg(short, long)]
    tx_file: String,

    /// Output traces path
    #[arg(short, long)]
    output: String,

    #[arg(long, value_enum, default_value_t = GroupKind::Lock)]
    script_group: GroupKind,

    #[arg(long, value_parser = parse_byte32)]
    script_hash: Option<Byte32>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.collector {
        CollectorKind::Syscall => run::<SyscallBasedCollector>(&cli),
        CollectorKind::TxParts => run::<TxPartsBasedCollector>(&cli),
    }
}

fn run<C>(cli: &Cli) -> Result<(), Box<dyn std::error::Error>>
where
    C: Collector + Send + 'static,
    Vec<u8>: From<<C as Collector>::Trace>,
{
    let collector: BinaryLocatorCollector<C> = BinaryLocatorCollector::default();

    // TODO: figure out later if utilities in ckb-debugger crate, such as
    // analyze is worth using.
    let mock_tx: ReprMockTransaction = if cli.tx_file == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        serde_json::from_str(&buf)
    } else {
        let buf = std::fs::read_to_string(&cli.tx_file)?;
        serde_json::from_str(&buf)
    }?;
    let verifier = collector.build_verifier(mock_tx)?;

    let script_group = if let Some(script_hash) = &cli.script_hash {
        verifier.find_script_group(cli.script_group.into(), script_hash)
    } else {
        None
    };

    if let Some(script_group) = script_group {
        match collector.collect(&verifier, script_group)? {
            CollectorResult::Success { traces, cycles } => {
                println!("Script group consumes {} cycles.", cycles);

                let output_path = Path::new(&cli.output);
                let vms = traces.len();
                let mut locators = HashMap::with_capacity(vms);
                for (key, (locator, trace)) in traces {
                    let string_key = format!("vm_{}_generation_{}", key.vm_id, key.generation_id);
                    locators.insert(string_key, locator);

                    let file_path = output_path.join(format!("vm_{}_{}.traces", key.vm_id, key.generation_id));
                    let bytes: Vec<u8> = trace.into();
                    std::fs::write(file_path, bytes)?
                }
                {
                    let locator_path = output_path.join("locators.json");
                    let data = serde_json::to_string_pretty(&locators)?;
                    std::fs::write(locator_path, data)?;
                }
                println!("Traces for {} VMs have been written to {}.", vms, cli.output);
            }
            CollectorResult::Failure { exit_code } => {
                println!("Root VM terminates with non-zero exit code: {}, terminating...", exit_code);
                std::process::abort();
            }
        }
    } else {
        println!("Either you didn't specify a script group, or the script group you provided does not exist!");
        println!("Please use one of the following script hash:\n");
        for (hash, group) in verifier.groups() {
            println!(
                "Script hash: {:#x} : script group type: {}, input cell indices: {:?}, output cell indices: {:?}.",
                hash, group.group_type, group.input_indices, group.output_indices
            );
        }
    }

    Ok(())
}
