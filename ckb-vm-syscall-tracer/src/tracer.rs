use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_mock_tx_types::{MockTransaction, ReprMockTransaction, Resource};
use ckb_script::{types::Machine, ScriptGroupType, TransactionScriptsVerifier, TxVerifyEnv};
use ckb_types::{
    core::{cell::resolve_transaction, hardfork, EpochNumberWithFraction, HeaderView},
    packed::Byte32,
    prelude::*,
};
use ckb_vm_syscall_tracer::{Collector, SyscallBasedCollector, TxPartsBasedCollector};
use clap::{Parser, ValueEnum};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum CollectorKind {
    /// Syscall based collector, data from each syscall are collected for replays.
    Syscall,

    /// Tx based collector, certain data are collected from the tx as a whole
    TxParts,
}

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
        CollectorKind::Syscall => run(SyscallBasedCollector::default(), &cli),
        CollectorKind::TxParts => run(TxPartsBasedCollector::default(), &cli),
    }
}

fn run<C: Collector>(collector: C, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = build_verifier(collector.clone(), &cli.tx_file)?;

    let script_group = if let Some(script_hash) = &cli.script_hash {
        verifier.find_script_group(cli.script_group.into(), script_hash)
    } else {
        None
    };

    if let Some(script_group) = script_group {
        let mut scheduler = verifier.create_scheduler(script_group)?;
        loop {
            let iteration_result = scheduler.iterate()?;
            if let Some((exit_code, cycles)) = iteration_result.exit_status {
                if exit_code != 0 {
                    println!("Root VM terminates with non-zero exit code: {}, terminating...", exit_code);
                    std::process::abort();
                }
                println!("Script group consumes {} cycles.", cycles);
                break;
            }
            collector.postprocess(&mut scheduler)?;
        }
        let data = collector.seal();
        let output_path = Path::new(&cli.output);
        let vms = data.len();
        for (vm_id, trace) in data {
            let file_path = output_path.join(format!("vm_{}.traces", vm_id));
            let bytes: Vec<u8> = trace.into();
            std::fs::write(file_path, bytes)?
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
    }

    Ok(())
}

fn build_verifier<C: Collector>(
    collector: C,
    tx_file: &str,
) -> Result<TransactionScriptsVerifier<Resource, C, Machine>, Box<dyn std::error::Error>> {
    // TODO: figure out later if utilities in ckb-debugger crate, such as
    // analyze is worth using.
    let mock_tx: MockTransaction = if tx_file == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        let repr_mock_tx: ReprMockTransaction = serde_json::from_str(&buf)?;
        repr_mock_tx.into()
    } else {
        let buf = std::fs::read_to_string(tx_file)?;
        let repr_mock_tx: ReprMockTransaction = serde_json::from_str(&buf)?;
        repr_mock_tx.into()
    };

    let resource = Resource::from_mock_tx(&mock_tx)?;
    let resolved_transaction =
        resolve_transaction(mock_tx.core_transaction(), &mut HashSet::new(), &resource, &resource)?;

    let hardforks = hardfork::HardForks {
        ckb2021: hardfork::CKB2021::new_mirana().as_builder().rfc_0032(20).build().unwrap(),
        ckb2023: hardfork::CKB2023::new_mirana().as_builder().rfc_0049(30).build().unwrap(),
    };
    let consensus = Arc::new(ConsensusBuilder::default().hardfork_switch(hardforks).build());
    let epoch = EpochNumberWithFraction::new(35, 0, 1);
    let header_view = HeaderView::new_advanced_builder().epoch(epoch.pack()).build();
    let tx_env = Arc::new(TxVerifyEnv::new_commit(&header_view));
    Ok(TransactionScriptsVerifier::new_with_generator(
        Arc::new(resolved_transaction),
        resource,
        consensus,
        tx_env,
        C::syscall_generator,
        collector.clone(),
    ))
}
