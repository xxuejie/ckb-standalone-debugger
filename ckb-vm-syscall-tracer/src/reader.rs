use ckb_vm_syscall_tracer::{Collector, CollectorKind, SyscallBasedCollector, TxPartsBasedCollector};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Collector to use
    #[arg(long, value_enum, default_value_t = CollectorKind::Syscall)]
    collector: CollectorKind,

    files: Vec<String>,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.collector {
        CollectorKind::Syscall => run::<SyscallBasedCollector>(&cli),
        CollectorKind::TxParts => run::<TxPartsBasedCollector>(&cli),
    }
}

fn run<C: Collector>(cli: &Cli) -> Result<(), String>
where
    std::string::String: for<'a> From<<<C as Collector>::Trace as TryFrom<&'a [u8]>>::Error>,
{
    for file in &cli.files {
        let data = std::fs::read(file).map_err(|e| format!("IO error: {}", e))?;
        let trace = C::Trace::try_from(&data)?;

        println!("Content for {}:", file);
        println!("{:?}", trace);
        println!();
    }
    Ok(())
}
