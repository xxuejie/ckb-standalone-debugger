use ckb_mock_tx_types::{MockTransaction, ReprMockTransaction};
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum CellKind {
    Input,
    Output,
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

    #[arg(long, value_enum, default_value_t = CellKind::Input)]
    cell_kind: CellKind,

    #[arg(long)]
    cell_index: Option<usize>,
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
    let repr_tx: ReprMockTransaction = if cli.tx_file == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        serde_json::from_str(&buf)
    } else {
        let buf = std::fs::read_to_string(&cli.tx_file)?;
        serde_json::from_str(&buf)
    }?;
    let mock_tx: MockTransaction = repr_tx.into();
    let verifier = collector.build_verifier(&mock_tx)?;

    let script_group = if let Some(script_hash) = &cli.script_hash {
        verifier.find_script_group(cli.script_group.into(), script_hash)
    } else if let Some(cell_index) = cli.cell_index {
        let cell_output = match cli.cell_kind {
            CellKind::Input => mock_tx.mock_info.inputs.get(cell_index).map(|mock_input| mock_input.output.clone()),
            CellKind::Output => mock_tx.tx.raw().outputs().get(cell_index),
        };
        let script = cell_output.and_then(|cell_output| match cli.script_group {
            GroupKind::Lock => Some(cell_output.lock()),
            GroupKind::Type => cell_output.type_().to_opt(),
        });
        script.and_then(|script| verifier.find_script_group(cli.script_group.into(), &script.calc_script_hash()))
    } else {
        None
    };

    if let Some(script_group) = script_group {
        let CollectorResult { exit_code, cycles, traces } = collector.collect(&verifier, script_group)?;
        println!("Root VM exit code: {}.", exit_code);
        println!("Script group consumes {} cycles.", cycles);

        let output_path = Path::new(&cli.output);
        std::fs::create_dir_all(&output_path).expect("mkdir -p");

        let vms = traces.len();
        let mut locators = HashMap::with_capacity(vms);
        for (key, (locator, trace)) in traces {
            let vm_name = format!("vm_{}_{}", key.vm_id, key.generation_id);
            locators.insert(vm_name.clone(), locator);

            let file_path = output_path.join(format!("{}.traces", vm_name));
            let bytes: Vec<u8> = trace.into();
            std::fs::write(file_path, bytes)?
        }
        {
            let locator_path = output_path.join("locators.json");
            let data = serde_json::to_string_pretty(&locators)?;
            std::fs::write(locator_path, data)?;
        }
        println!("Traces for {} VMs have been written to {}.", vms, cli.output);
    } else {
        println!("Either you didn't specify a script group, or the script group you provided does not exist!");
        println!("Please use one of the following script hash:\n");
        for (hash, group) in verifier.groups() {
            println!(
                "Script hash: {:#x} : script group type: {}, input cell indices: {:?}, output cell indices: {:?}.",
                hash, group.group_type, group.input_indices, group.output_indices
            );
        }
        std::process::exit(1);
    }

    Ok(())
}
