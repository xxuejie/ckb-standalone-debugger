use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_mock_tx_types::{MockTransaction, ReprMockTransaction, Resource};
use ckb_script::{types::Machine, TransactionScriptsVerifier, TxVerifyEnv};
use ckb_types::{
    core::{cell::resolve_transaction, hardfork, EpochNumberWithFraction, HeaderView},
    prelude::*,
};
use ckb_vm_syscall_tracer::{Collector, SyscallBasedCollector};
use clap::Parser;
use std::collections::HashSet;
use std::io::Read;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Input mock tx file
    #[arg(short, long)]
    tx_file: String,

    /// Output traces path
    #[arg(short, long)]
    output: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // TODO: figure out later if utilities in ckb-debugger crate, such as
    // analyze is worth using.
    let mock_tx: MockTransaction = if cli.tx_file == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        let repr_mock_tx: ReprMockTransaction = serde_json::from_str(&buf)?;
        repr_mock_tx.into()
    } else {
        let buf = std::fs::read_to_string(&cli.tx_file)?;
        let repr_mock_tx: ReprMockTransaction = serde_json::from_str(&buf)?;
        repr_mock_tx.into()
    };

    let resource = Resource::from_mock_tx(&mock_tx)?;
    let resolved_transaction =
        resolve_transaction(mock_tx.core_transaction(), &mut HashSet::new(), &resource, &resource)?;

    let collector = SyscallBasedCollector::default();
    let verifier: TransactionScriptsVerifier<_, _, Machine> = {
        let hardforks = hardfork::HardForks {
            ckb2021: hardfork::CKB2021::new_mirana().as_builder().rfc_0032(20).build().unwrap(),
            ckb2023: hardfork::CKB2023::new_mirana().as_builder().rfc_0049(30).build().unwrap(),
        };
        let consensus = Arc::new(ConsensusBuilder::default().hardfork_switch(hardforks).build());
        let epoch = EpochNumberWithFraction::new(35, 0, 1);
        let header_view = HeaderView::new_advanced_builder().epoch(epoch.pack()).build();
        let tx_env = Arc::new(TxVerifyEnv::new_commit(&header_view));
        TransactionScriptsVerifier::new_with_generator(
            Arc::new(resolved_transaction),
            resource,
            consensus,
            tx_env,
            // TODO: make it a cli flag
            SyscallBasedCollector::syscall_generator,
            collector.clone(),
        )
    };

    // TODO: verify one at a time, make place for postprocess
    verifier.verify(u64::MAX)?;

    let data = collector.seal();

    Ok(())
}
