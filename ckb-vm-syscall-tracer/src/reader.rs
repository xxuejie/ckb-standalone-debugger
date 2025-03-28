use ckb_vm::Error;
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

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    match cli.collector {
        CollectorKind::Syscall => run::<SyscallBasedCollector>(&cli),
        CollectorKind::TxParts => run::<TxPartsBasedCollector>(&cli),
    }
}

fn run<C>(cli: &Cli) -> Result<(), Error>
where
    C: Collector<Trace: for<'a> TryFrom<&'a [u8], Error = Error> + std::fmt::Debug>,
{
    for file in &cli.files {
        let data = std::fs::read(file).map_err(|e| Error::IO { kind: e.kind(), data: format!("{}", e) })?;
        let trace = C::Trace::try_from(&data)?;

        println!("Content for {}:", file);
        println!("{:?}", trace);
        println!();
    }
    Ok(())
}
