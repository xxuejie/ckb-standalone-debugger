use clap::Parser;
use gecko_profile::{Frame, ProfileBuilder, ThreadBuilder};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter};
use std::str::FromStr;
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Input file
    #[arg(long)]
    input: String,

    /// Output file
    #[arg(long)]
    output: String,

    /// Frequency, default value is 0.5Ghz
    #[arg(long, default_value_t = 500000000)]
    frequency: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let lines: Box<dyn Iterator<Item = Result<String, io::Error>>> = if cli.input == "-" {
        Box::new(io::stdin().lines())
    } else {
        let file = File::open(&&cli.input).expect("open file");
        Box::new(BufReader::new(file).lines())
    };

    let start_time = Instant::now();
    let mut builder = ThreadBuilder::new(1, 0, start_time, false, false);
    let mut last_sampled_time = Instant::now();

    for line in lines {
        let line = line?;
        let i = line.rfind(" ").expect("no cycles available!");

        let stack: Vec<Frame> = line[0..i]
            .split("; ")
            .map(|s| {
                let func_name = match s.find(":") {
                    Some(j) => normalize_function_name(&s[j + 1..s.len()]),
                    None => normalize_function_name(s),
                };
                Frame::Label(builder.intern_string(&func_name))
            })
            .collect();
        let cycles = u64::from_str(&line[i + 1..line.len()]).expect("invalid cycle");

        let cpu_delta = Duration::from_nanos(1_000_000_000u64 * cycles / cli.frequency);
        builder.add_sample(last_sampled_time, stack.into_iter(), cpu_delta);
        last_sampled_time += cpu_delta;
    }

    let mut profile_builder =
        ProfileBuilder::new(start_time, std::time::SystemTime::now(), "CKB-VM", 0, std::time::Duration::from_micros(1));
    profile_builder.add_thread(builder);

    {
        let f = BufWriter::new(File::create(&cli.output)?);
        serde_json::to_writer(f, &profile_builder.to_serializable())?;
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Symbol {
    pub name: Option<String>,
    pub file: Option<String>,
}

impl Symbol {
    pub fn name(&self) -> String {
        self.name.clone().unwrap_or("<Unknown>".to_owned())
    }

    pub fn file(&self) -> String {
        self.file.clone().unwrap_or("<Unknown>".to_owned())
    }
}

fn normalize_function_name(name: &str) -> String {
    name.to_string()
}
